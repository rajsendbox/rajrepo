// Retrieve attributes and permission context
var envAttributes = $evaluation.getContext().getAttributes().toMap();
var userId = $evaluation.getContext().getIdentity().getId();
var userAttr = $evaluation.getContext().getIdentity().getAttributes().toMap();
var resourceId = $evaluation.getPermission().getResource().getId();
var resourceName = $evaluation.getPermission().getResource().getName();
var resourceUri = $evaluation.getPermission().getResource().getUris();
var resourceAttr = $evaluation.getPermission().getResource().getAttributes();
var claims = $evaluation.getPermission().getClaims();

// Safely retrieve the `org_id` claim (provided by the authorizer)
var claimOrgString = null;
if (claims && claims.containsKey('org_id')) {
    claimOrgString = claims.get('org_id').iterator().next();
}

// Parse `claimOrgString` into a list if it's a stringified list
var claimOrgs = [];
if (claimOrgString) {
    try {
        claimOrgs = JSON.parse(claimOrgString); // Parse JSON string into a list
    } catch (e) {
        print("Failed to parse claimOrgString: " + claimOrgString);
        claimOrgs = [claimOrgString]; // Fallback to treating it as a single org
    }
}

// Safely retrieve the user's organizations
var userOrgs = userAttr.get('organization');
if (!userOrgs) {
    userOrgs = []; // Default to an empty array if the user has no organization attribute
}

// Debugging: Print all relevant information
print("================");
print("envAttributes: " + envAttributes);
print("userId: " + userId);
print("userAttr: " + userAttr);
print("resourceId: " + resourceId);
print("resourceName: " + resourceName);
print("resourceUri: " + resourceUri);
print("resourceAttr: " + resourceAttr);
print("claims: " + claims);
print("claimOrgString: " + claimOrgString);
print("Parsed claimOrgs: " + JSON.stringify(claimOrgs));
print("userOrgs: " + userOrgs);
print("================");

// Grant access if claimOrgs is empty
if (claimOrgs.length === 0) {
    print("Access granted. No claimed organizations specified.");
    $evaluation.grant();
} else {
    // Check if the user's organizations include any of the claimed organizations
    var accessGranted = false;
    for (var i = 0; i < claimOrgs.length; i++) {
        if (userOrgs.indexOf(claimOrgs[i]) !== -1) {
            accessGranted = true;
            break;
        }
    }

    if (accessGranted) {
        print("Access granted. User belongs to one of the organizations: " + JSON.stringify(claimOrgs));
        $evaluation.grant();
    } else {
        print("Access denied. User does not belong to any of the organizations: " + JSON.stringify(claimOrgs));
        $evaluation.deny();
    }
}
