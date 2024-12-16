// Import necessary functions from the loginHandler module
import { addGroupsWithAttributes, addEmail, changeFullname, changeUsername } from './loginHandler';
import mysql from 'mysql2/promise'; // Import MySQL library for database connection

// Initialize Oidc object and httpCa variable for later use
Oidc = {};
httpCa = false;

// Check if a custom CA certificate is specified via environment variables
if (process.env.OAUTH2_CA_CERT !== undefined) {
    try {
        const fs = Npm.require('fs'); // Import the Node.js filesystem module
        if (fs.existsSync(process.env.OAUTH2_CA_CERT)) {
            // Read the contents of the CA certificate file
            httpCa = fs.readFileSync(process.env.OAUTH2_CA_CERT);
        }
    } catch (e) {
        // Log a warning if the certificate file cannot be loaded
        console.log('WARNING: failed loading: ' + process.env.OAUTH2_CA_CERT);
        console.log(e);
    }
}

// Initialize global variables to hold user information
var profile = {}; // Stores the user's profile data
var serviceData = {}; // Stores service-specific data such as tokens
var userinfo = {}; // Holds information about the user fetched from the OIDC provider

// Function to check if email exists in the MySQL database
async function emailExistsInDatabase(email) {
    const dbHost = process.env.MYSQL_HOST;
    const dbUser = process.env.MYSQL_USER;
    const dbPassword = process.env.MYSQL_PASSWORD;
    const dbName = process.env.MYSQL_DATABASE;
    const dbTable = process.env.MYSQL_TABLE || 'users'; // Default table name
    const dbEmailField = process.env.MYSQL_EMAIL_FIELD || 'email'; // Default email field

    let connection;
    try {
        // Create a connection to the MySQL database
        connection = await mysql.createConnection({
            host: dbHost,
            user: dbUser,
            password: dbPassword,
            database: dbName
        });

        // Query to check if the email exists
        const [rows] = await connection.execute(
            `SELECT COUNT(*) as count FROM \\`${dbTable}\\` WHERE \\`${dbEmailField}\\` = ?`,
            [email]
        );

        return rows[0].count > 0; // Return true if email exists, false otherwise
    } catch (err) {
        console.error('Database query error:', err);
        throw new Error('Failed to validate email in the database.');
    } finally {
        if (connection) await connection.end(); // Ensure connection is closed
    }
}

// Register the OIDC service for the OAuth flow
OAuth.registerService('oidc', 2, null, async function (query) {
    var debug = process.env.DEBUG === 'true'; // Enable debug mode based on environment variable

    // Retrieve the token using the query parameters provided by the OAuth flow
    var token = getToken(query);
    if (debug) console.log('XXX: register token:', token);

    // Extract access and expiration tokens from the retrieved token
    var accessToken = token.access_token || token.id_token;
    var expiresAt = (+new Date) + (1000 * parseInt(token.expires_in, 10)); // Calculate expiration time

    // Determine if claims should be extracted directly from the access token
    var claimsInAccessToken = (
        process.env.OAUTH2_ADFS_ENABLED === 'true' ||
        process.env.OAUTH2_ADFS_ENABLED === true ||
        process.env.OAUTH2_B2C_ENABLED === 'true' ||
        process.env.OAUTH2_B2C_ENABLED === true
    ) || false;

    if (claimsInAccessToken) {
        // For certain configurations (ADFS, B2C), extract claims from the token
        userinfo = getTokenContent(accessToken);
    } else {
        // Otherwise, fetch user information from the OIDC UserInfo endpoint
        userinfo = getUserInfo(accessToken);
    }

    // Handle specific hacks for Nextcloud and OpenShift platforms
    if (userinfo.ocs) userinfo = userinfo.ocs.data; // Extract relevant data for Nextcloud
    if (userinfo.metadata) userinfo = userinfo.metadata; // Extract relevant data for OpenShift

    if (debug) console.log('XXX: userinfo:', userinfo);

    // Map user information to serviceData using environment-configured keys
    serviceData.id = userinfo[process.env.OAUTH2_ID_MAP]; // User ID
    serviceData.username = userinfo[process.env.OAUTH2_USERNAME_MAP]; // Username
    serviceData.fullname = userinfo[process.env.OAUTH2_FULLNAME_MAP]; // Full name
    serviceData.accessToken = accessToken; // Access token
    serviceData.expiresAt = expiresAt; // Token expiration time

    // Handle email mapping for Oracle OIM, falling back to username if necessary
    if (process.env.ORACLE_OIM_ENABLED === 'true' || process.env.ORACLE_OIM_ENABLED === true) {
        serviceData.email = userinfo[process.env.OAUTH2_EMAIL_MAP] || userinfo[process.env.OAUTH2_USERNAME_MAP];
    } else {
        serviceData.email = userinfo[process.env.OAUTH2_EMAIL_MAP];
    }

    // For Azure AD B2C, handle email differently
    if (process.env.OAUTH2_B2C_ENABLED === 'true' || process.env.OAUTH2_B2C_ENABLED === true) {
        serviceData.email = userinfo["emails"][0];
    }

    if (debug) console.log('XXX: serviceData.email:', serviceData.email);

    // Check email against the database
    const emailExists = await emailExistsInDatabase(serviceData.email);
    if (!emailExists) {
        throw new Error('Email validation failed: Email not found in the database.');
    }

    // If additional fields are whitelisted in the configuration, extend serviceData with them
    if (accessToken) {
        var tokenContent = getTokenContent(accessToken);
        var fields = _.pick(tokenContent, getConfiguration().idTokenWhitelistFields); // Pick specified fields
        _.extend(serviceData, fields); // Merge the fields into serviceData
    }

    // Store the refresh token if available
    if (token.refresh_token) serviceData.refreshToken = token.refresh_token;

    if (debug) console.log('XXX: serviceData:', serviceData);

    // Map user profile fields
    profile.name = userinfo[process.env.OAUTH2_FULLNAME_MAP];
    profile.email = userinfo[process.env.OAUTH2_EMAIL_MAP];

    // For Azure AD B2C, handle profile email differently
    if (process.env.OAUTH2_B2C_ENABLED === 'true' || process.env.OAUTH2_B2C_ENABLED === true) {
        profile.email = userinfo["emails"][0];
    }

    if (debug) console.log('XXX: profile:', profile);

    // Temporarily store group information in serviceData.groups for later processing
    serviceData.groups = (userinfo["groups"] && userinfo["wekanGroups"]) ? userinfo["wekanGroups"] : userinfo["groups"];

    // If groups are simple strings (no scope attributes), transform them into structured objects
    if (Array.isArray(serviceData.groups) && serviceData.groups.length && typeof serviceData.groups[0] === "string") {
        user = Meteor.users.findOne({ '_id': serviceData.id });

        // Iterate over the group names and structure them
        serviceData.groups.forEach(function (groupName, i) {
            if (user?.isAdmin && i === 0) {
                // Preserve admin privileges for the first group
                serviceData.groups[i] = { "isAdmin": true, "displayName": groupName };
            } else {
                serviceData.groups[i] = { "displayName": groupName };
            }
        });
    }

    // Call routines for group and board processing during login
    Meteor.call('groupRoutineOnLogin', serviceData, "" + serviceData.id);
    Meteor.call('boardRoutineOnLogin', serviceData, "" + serviceData.id);

    // Return the mapped serviceData and profile to complete the login flow
    return {
        serviceData: serviceData,
        options: { profile: profile }
    };
});

// Set a user agent string for HTTP requests
var userAgent = "Meteor";
if (Meteor.release) {
    userAgent += "/" + Meteor.release;
}

// Function to retrieve token from the OIDC token endpoint
var getToken = function (query) {
    var debug = process.env.DEBUG === 'true'; // Enable debug mode for detailed logging
    var config = getConfiguration(); // Fetch the OIDC service configuration

    // Determine the full URL for the token endpoint
    var serverTokenEndpoint = config.tokenEndpoint.includes('https://')
        ? config.tokenEndpoint
        : config.serverUrl + config.tokenEndpoint;

    try {
        // Set up the POST request options to fetch the token
        var postOptions = {
            headers: {
                Accept: 'application/json',
                "User-Agent": userAgent
            },
            params: {
                code: query.code, // Authorization code
                client_id: config.clientId, // Client ID
                client_secret: OAuth.openSecret(config.secret), // Client secret
                redirect_uri: OAuth._redirectUri('oidc', config), // Redirect URI
                grant_type: 'authorization_code', // Authorization grant type
                state: query.state // State parameter for validation
            }
        };

        // If a CA certificate is defined, add it to the request options
        if (httpCa) {
            postOptions['npmRequestOptions'] = { ca: httpCa };
        }

        // Send the POST request to fetch the token
        var response = HTTP.post(serverTokenEndpoint, postOptions);
    } catch (err) {
        // Handle errors during the token request
        throw _.extend(new Error("Failed to get token from OIDC " + serverTokenEndpoint + ": " + err.message), {
            response: err.response
        });
    }

    // If the response contains an error, throw it
    if (response.data.error) {
        throw new Error("Failed to complete handshake with OIDC " + serverTokenEndpoint + ": " + response.data.error);
    } else {
        if (debug) console.log('XXX: getToken response: ', response.data);
        return response.data; // Return the token data
    }
};

// Function to fetch user information from the UserInfo endpoint
var getUserInfo = function (accessToken) {
    var debug = process.env.DEBUG === 'true'; // Enable debug mode for detailed logging
    var config = getConfiguration(); // Fetch the OIDC service configuration

    // Determine the full URL for the UserInfo endpoint
    var serverUserinfoEndpoint = config.userinfoEndpoint.includes("https://")
        ? config.userinfoEndpoint
        : config.serverUrl + config.userinfoEndpoint;

    try {
        // Set up the GET request options to fetch user info
        var getOptions = {
            headers: {
                "User-Agent": userAgent, // User agent string
                "Authorization": "Bearer " + accessToken // Access token for authorization
            }
        };

        // If a CA certificate is defined, add it to the request options
        if (httpCa) {
            getOptions['npmRequestOptions'] = { ca: httpCa };
        }

        // Send the GET request to fetch user info
        var response = HTTP.get(serverUserinfoEndpoint, getOptions);
    } catch (err) {
        // Handle errors during the user info request
        throw _.extend(new Error("Failed to fetch userinfo from OIDC " + serverUserinfoEndpoint + ": " + err.message), {
            response: err.response
        });
    }

    if (debug) console.log('XXX: getUserInfo response: ', response.data);
    return response.data; // Return the user info
};

// Function to fetch and validate OIDC configuration
var getConfiguration = function () {
    var config = ServiceConfiguration.configurations.findOne({ service: 'oidc' }); // Fetch configuration from database
    if (!config) {
        // Throw an error if the configuration is missing
        throw new ServiceConfiguration.ConfigError('Service oidc not configured.');
    }
    return config;
};

// Function to decode the content of a JWT token
var getTokenContent = function (token) {
    var content = null;
    if (token) {
        try {
            // Split the token into its header, payload, and signature parts
            var parts = token.split('.');
            var header = JSON.parse(Buffer.from(parts[0], 'base64').toString()); // Decode the header
            content = JSON.parse(Buffer.from(parts[1], 'base64').toString()); // Decode the payload (claims)
            var signature = Buffer.from(parts[2], 'base64'); // Decode the signature
            var signed = parts[0] + '.' + parts[1]; // Combine header and payload for verification
        } catch (err) {
            // If decoding fails, default the expiration to 0
            this.content = { exp: 0 };
        }
    }
    return content; // Return the decoded content
};

// Meteor method to handle group-related tasks during login
Meteor.methods({
    'groupRoutineOnLogin': function (info, userId) {
        check(info, Object); // Validate the info parameter
        check(userId, String); // Validate the userId parameter

        var propagateOidcData = process.env.PROPAGATE_OIDC_DATA || false; // Determine if data propagation is enabled
        if (propagateOidcData) {
            users = Meteor.users; // Reference to the Meteor users collection
            user = users.findOne({ 'services.oidc.id': userId }); // Find the user by their OIDC ID

            if (user) {
                // Update or create groups and privileges based on OIDC data
                if (info.groups) {
                    addGroupsWithAttributes(user, info.groups);
                }
                if (info.email) addEmail(user, info.email);
                if (info.fullname) changeFullname(user, info.fullname);
                if (info.username) changeUsername(user, info.username);
				        }
    }
});

// Meteor method to handle board-related tasks during login
Meteor.methods({
    'boardRoutineOnLogin': function (info, userId) {
        check(info, Object); // Validate the info parameter
        check(userId, String); // Validate the userId parameter

        // Placeholder for board-specific tasks or logic
        // You can add custom functionality here to handle board data
        console.log("Board routine executed for user ID:", userId);
    }
});

// Function to retrieve OAuth credentials
Oidc.retrieveCredential = function (credentialToken, credentialSecret) {
    return OAuth.retrieveCredential(credentialToken, credentialSecret); // Call the built-in OAuth method
};
