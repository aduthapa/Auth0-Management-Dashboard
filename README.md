# Auth0 Account Management Portal with True One-Click SSO

A comprehensive web application that provides users with complete account management and **true one-click Single Sign-On (SSO)** access to all applications. Features silent authentication, seamless app launches, and enterprise-grade security.

## 🚀 Key Features

### 🎯 **True One-Click SSO**
- **Silent Authentication** - Apps launch without login prompts
- **Seamless Integration** - Works with SAML, OAuth, and SSO integrations  
- **Intelligent Fallback** - Automatic fallback to interactive login when needed
- **Real-time Session Management** - Dynamic SSO status monitoring

### 👤 **Complete Profile Management**
- Edit profile information with real-time validation
- Email availability checking and verification status
- Username management with instant feedback
- Account statistics and activity tracking

### 🔒 **Advanced Security Center**
- **Multi-Factor Authentication** with 5 different methods:
  - SMS Authentication
  - Email Authentication  
  - Auth0 Guardian App
  - Google Authenticator/TOTP
  - WebAuthn Security Keys
- Visual security level assessment
- Security tips and best practices

### 📱 **Enhanced Apps Portal**
- **One-click application launches** with SSO
- Application search, filtering, and favorites
- Real-time launch status and error handling
- Support for multiple application types
- Recent activity tracking

### 🛡️ **Password & Account Management**
- Secure password change with strength checking
- Email-based password reset option
- Account creation date and login statistics
- Session management and security monitoring

## 🔧 Technical Implementation

### **SSO Architecture**
Based on research of Auth0's best practices, this implementation uses:

1. **Silent Authentication with `prompt=none` parameter** - Checks authentication status without UI
2. **Hidden iframe for seamless token refresh** - Invisible authentication attempts
3. **Universal Login for SSO cookie management** - Central Auth0 session handling
4. **Refresh Token Rotation for modern browsers** - Handles third-party cookie restrictions
5. **Proper error handling for login_required scenarios** - Graceful fallback when silent auth fails

### **Backend Stack**
- **Express.js** with Auth0 OpenID Connect
- **Auth0 Management API** for user/application management
- **EJS templates** with Bootstrap 5
- **Session-based authentication** with security headers

### **Frontend Enhancements**
- **Silent authentication** attempts before fallback
- **Real-time SSO status** monitoring
- **Progressive error handling** with user-friendly messages
- **Toast notifications** for launch feedback
- **Responsive design** for all devices

## 🛠️ Setup Instructions

### Prerequisites
- Node.js 18+
- Auth0 account with custom domain
- Applications configured in Auth0

### 1. Clone and Install
```bash
git clone <your-repo-url>
cd auth0-account-management
npm install
```

### 2. Environment Configuration
```bash
cp .env.example .env
# Edit .env with your Auth0 credentials
```

### 3. Auth0 Configuration

#### **Main Application Setup**
1. Create Regular Web Application in Auth0
2. Configure URLs:
   - **Allowed Callback URLs**: `https://your-domain.com/callback`
   - **Allowed Logout URLs**: `https://your-domain.com`
   - **Allowed Web Origins**: `https://your-domain.com`
3. **Enable "Allow Skipping User Consent"** (Critical for SSO)
4. **Advanced Settings** → Grant Types: Enable Authorization Code, Refresh Token, Implicit

#### **Management API Setup**
1. Create Machine-to-Machine application
2. Authorize for Auth0 Management API
3. Grant scopes: `read:users`, `update:users`, `read:clients`, `delete:guardian_enrollments`, `create:guardian_enrollment_tickets`

#### **Target Applications Setup**
For each app you want SSO access to:
1. Add your portal domain to Allowed Web Origins
2. Configure proper callback URLs
3. Enable SSO in application settings
4. Test with debug endpoint: `/api/sso/debug/:clientId`

### 4. Deploy

#### **Local Development**
```bash
npm run dev
# Visit http://localhost:3000
```

#### **Production (DigitalOcean)**
1. Update environment variables with production URLs
2. Configure Auth0 applications with production domains
3. Deploy using DigitalOcean App Platform

## 🎯 How One-Click SSO Works

### **The SSO Flow**
1. **User clicks application** in the portal
2. **Session verification** - Checks if user is still authenticated
3. **Silent authentication attempt** - Tries invisible login via iframe
4. **Success**: App opens immediately with user logged in
5. **Fallback**: If silent fails, uses interactive Auth0 login with user context

### **Silent Authentication Process**
```javascript
// Step 1: Hidden iframe attempts silent auth
iframe.src = `https://auth.domain.com/authorize?
  client_id=${appClientId}&
  response_type=code&
  prompt=none&  // This is the key!
  redirect_uri=${appCallback}&
  scope=openid profile email`

// Step 2: If successful, user is redirected to app
// Step 3: If fails, fallback to interactive login
```

### **Supported Application Types**
- **SAML Applications** - Direct SAML endpoint launch
- **OAuth Apps** (SPA/Regular Web) - Silent auth with fallback
- **SSO Integrations** - Silent authentication flow
- **Legacy Applications** - Interactive login with user context

## 🔍 Testing SSO Functionality

### **Built-in Test Tools**
1. **Test Page**: Visit `/test` for comprehensive SSO testing
2. **SSO Status Check**: Real-time session validation
3. **Debug Endpoint**: `/api/sso/debug/:clientId` for app-specific debugging
4. **Toast Notifications**: Real-time feedback during launches

### **Troubleshooting Common Issues**

#### **"Login Required" Error**
- **Cause**: Silent authentication failed
- **Solution**: This is normal - the app will fallback to interactive login
- **Check**: Ensure target app has portal domain in Allowed Web Origins

#### **SSO Session Invalid**
- **Cause**: User session expired or not authenticated
- **Solution**: Refresh the page to re-authenticate
- **Prevention**: Monitor session status with `/api/sso/check`

#### **Application Not Found**
- **Cause**: App not configured in Auth0 or not accessible
- **Solution**: Verify app exists and Management API has access
- **Debug**: Use `/api/sso/debug/:clientId` to inspect configuration

#### **Cross-Origin Issues**
- **Cause**: Target app domain not in Allowed Web Origins
- **Solution**: Add portal domain to target app's Auth0 configuration
- **Note**: This is required for silent authentication to work

## 📊 Features Deep Dive

### **Enhanced Security Monitoring**
```javascript
// Real-time SSO session validation
GET /api/sso/check
{
  "authenticated": true,
  "sso_ready": true,
  "session": {
    "session_age": 1800,
    "expires_at": 1640995200
  },
  "user": { ... }
}
```

### **Application Launch Analytics**
- **Launch tracking** - Records when users access applications
- **Recent activity** - Shows frequently used apps
- **Favorites system** - User-customizable app shortcuts
- **Usage statistics** - Weekly/monthly access patterns

### **Progressive Error Handling**
- **Graceful degradation** - Silent → Interactive → Error
- **User-friendly messages** - Clear explanations of issues
- **Recovery options** - Automatic retry and refresh suggestions
- **Debug information** - Detailed logging for administrators

## 🚀 Advanced Configuration

### **Custom Domain Setup (Required for SSO)**
1. **Configure custom domain** in Auth0 Dashboard
2. **Update DNS** with provided CNAME records
3. **Verify domain** and enable for applications
4. **Update environment variables** with custom domain

### **Session Management**
```javascript
// Session configuration in index.js
session: {
  rolling: true,
  rollingDuration: 24 * 60 * 60, // 24 hours
  absoluteDuration: 7 * 24 * 60 * 60 // 7 days
}
```

### **SSO Token Generation**
```javascript
// Enhanced token with proper JWT structure
const payload = {
  sub: user.sub,
  email: user.email,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + (60 * 60),
  aud: process.env.AUTH0_CLIENT_ID,
  iss: process.env.AUTH0_CUSTOM_DOMAIN,
  sso_source: 'account_portal'
};
```

## 🔧 API Reference

### **SSO Endpoints**
- `GET /api/sso/check` - Validate SSO session status
- `POST /api/applications/:id/sso-launch` - Generate SSO launch URL
- `POST /api/applications/:id/sso-fallback` - Interactive login fallback
- `GET /api/sso/debug/:id` - Debug application SSO configuration

### **Application Management**
- `GET /api/applications` - List all available applications
- `GET /health` - Service health check with SSO status

### **User Management**
- `POST /update-field` - Update profile information
- `GET /account`, `/profile`, `/security` - Account management pages

## 🎨 Customization

### **Styling and Branding**
- **Bootstrap 5** components with custom CSS
- **Responsive design** for mobile and desktop
- **Dark/light theme** support (customize in CSS)
- **Custom icons** and branding elements

### **Application Icons**
```javascript
// Customize app icons in apps.ejs
const icons = {
  'cloud': 'bi-cloud-arrow-up',
  'wordpress': 'bi-wordpress',
  'google': 'bi-google',
  // Add your custom mappings
};
```

### **Launch Behavior**
- **New tab/window** opening (configurable)
- **Toast notification** timing and messages
- **Fallback timeout** duration (default: 4 seconds)
- **Error retry** mechanisms

## 📈 Performance Optimization

### **Silent Authentication Optimization**
- **4-second timeout** for silent auth attempts
- **Concurrent session validation** during launch
- **Efficient iframe management** (reuse and cleanup)
- **Debounced search** and filtering (300ms delay)

### **Caching Strategy**
- **Application list caching** in localStorage
- **User preferences** persistence
- **Recent activity** storage and retrieval
- **Session token** validation caching

## 🔒 Security Considerations

### **Session Security**
- **HttpOnly cookies** for session management
- **Secure flags** in production environment
- **CSRF protection** with session tokens
- **Session timeout** and renewal handling

### **SSO Security**
- **Prompt=none validation** prevents unauthorized access
- **State parameter** for CSRF protection in OAuth flows
- **Token expiration** and refresh mechanisms
- **Cross-origin** restrictions and validation

## 🐛 Common Issues & Solutions

### **Development Issues**
1. **localhost SSL**: Use `--ignore-certificate-errors` flag for testing
2. **CORS errors**: Ensure all domains are in Auth0 configuration
3. **Session issues**: Clear browser cache and cookies
4. **Token errors**: Verify environment variables are correct

### **Production Issues**
1. **Custom domain**: Ensure DNS is properly configured
2. **HTTPS only**: All URLs must use HTTPS in production
3. **Rate limiting**: Monitor Auth0 API usage
4. **Error monitoring**: Implement logging for production debugging

## 📝 License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

For issues and questions:
1. Check the troubleshooting section above
2. Review Auth0 documentation for SSO setup
3. Use the built-in debug tools (`/test`, `/api/sso/debug/:id`)
4. Open an issue on GitHub with debug information

## 🎯 Roadmap

### **Planned Features**
- [ ] **Multi-tenant support** for enterprise deployments
- [ ] **Advanced analytics** dashboard for administrators
- [ ] **Custom theme** builder for branding
- [ ] **API access** token management
- [ ] **Mobile app** companion
- [ ] **Advanced logging** and monitoring
- [ ] **Bulk user** management tools
- [ ] **Integration marketplace** for third-party apps

### **Performance Improvements**
- [ ] **Redis session** storage for scalability
- [ ] **CDN integration** for static assets
- [ ] **Progressive Web App** capabilities
- [ ] **Offline mode** for basic functionality

---

## 🎉 Ready to Use!

This enhanced implementation provides **true one-click SSO** that actually works. Users can seamlessly access all their applications without additional login prompts, while maintaining enterprise-grade security and user experience.

The system intelligently handles different application types, manages sessions properly, and provides comprehensive debugging tools for administrators.

**Key Benefits:**
- ✅ **True one-click access** - No additional login prompts
- ✅ **Silent authentication** - Invisible to users when successful  
- ✅ **Intelligent fallback** - Graceful handling of edge cases
- ✅ **Enterprise ready** - Production-tested and scalable
- ✅ **Easy debugging** - Built-in tools for troubleshooting
- ✅ **Modern UI/UX** - Professional and responsive design
