// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Audit.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetEventsAuditEventDataIdentity {
    /**
     * @return The type of authentication used.  Example: `natv`
     * 
     */
    private final String authType;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the caller. The caller that made a  request on behalf of the prinicpal.
     * 
     */
    private final String callerId;
    /**
     * @return The name of the user or service. This value is the friendly name associated with `callerId`.
     * 
     */
    private final String callerName;
    /**
     * @return This value identifies any Console session associated with this request.
     * 
     */
    private final String consoleSessionId;
    /**
     * @return The credential ID of the user. This value is extracted from the HTTP &#39;Authorization&#39; request header. It consists of the tenantId, userId, and user fingerprint, all delimited by a slash (/).
     * 
     */
    private final String credentials;
    /**
     * @return The IP address of the source of the request.  Example: `172.24.80.88`
     * 
     */
    private final String ipAddress;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the principal.
     * 
     */
    private final String principalId;
    /**
     * @return The name of the user or service. This value is the friendly name associated with `principalId`.  Example: `ExampleName`
     * 
     */
    private final String principalName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenant.
     * 
     */
    private final String tenantId;
    /**
     * @return The user agent of the client that made the request.  Example: `Jersey/2.23 (HttpUrlConnection 1.8.0_212)`
     * 
     */
    private final String userAgent;

    @CustomType.Constructor
    private GetEventsAuditEventDataIdentity(
        @CustomType.Parameter("authType") String authType,
        @CustomType.Parameter("callerId") String callerId,
        @CustomType.Parameter("callerName") String callerName,
        @CustomType.Parameter("consoleSessionId") String consoleSessionId,
        @CustomType.Parameter("credentials") String credentials,
        @CustomType.Parameter("ipAddress") String ipAddress,
        @CustomType.Parameter("principalId") String principalId,
        @CustomType.Parameter("principalName") String principalName,
        @CustomType.Parameter("tenantId") String tenantId,
        @CustomType.Parameter("userAgent") String userAgent) {
        this.authType = authType;
        this.callerId = callerId;
        this.callerName = callerName;
        this.consoleSessionId = consoleSessionId;
        this.credentials = credentials;
        this.ipAddress = ipAddress;
        this.principalId = principalId;
        this.principalName = principalName;
        this.tenantId = tenantId;
        this.userAgent = userAgent;
    }

    /**
     * @return The type of authentication used.  Example: `natv`
     * 
     */
    public String authType() {
        return this.authType;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the caller. The caller that made a  request on behalf of the prinicpal.
     * 
     */
    public String callerId() {
        return this.callerId;
    }
    /**
     * @return The name of the user or service. This value is the friendly name associated with `callerId`.
     * 
     */
    public String callerName() {
        return this.callerName;
    }
    /**
     * @return This value identifies any Console session associated with this request.
     * 
     */
    public String consoleSessionId() {
        return this.consoleSessionId;
    }
    /**
     * @return The credential ID of the user. This value is extracted from the HTTP &#39;Authorization&#39; request header. It consists of the tenantId, userId, and user fingerprint, all delimited by a slash (/).
     * 
     */
    public String credentials() {
        return this.credentials;
    }
    /**
     * @return The IP address of the source of the request.  Example: `172.24.80.88`
     * 
     */
    public String ipAddress() {
        return this.ipAddress;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the principal.
     * 
     */
    public String principalId() {
        return this.principalId;
    }
    /**
     * @return The name of the user or service. This value is the friendly name associated with `principalId`.  Example: `ExampleName`
     * 
     */
    public String principalName() {
        return this.principalName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenant.
     * 
     */
    public String tenantId() {
        return this.tenantId;
    }
    /**
     * @return The user agent of the client that made the request.  Example: `Jersey/2.23 (HttpUrlConnection 1.8.0_212)`
     * 
     */
    public String userAgent() {
        return this.userAgent;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetEventsAuditEventDataIdentity defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String authType;
        private String callerId;
        private String callerName;
        private String consoleSessionId;
        private String credentials;
        private String ipAddress;
        private String principalId;
        private String principalName;
        private String tenantId;
        private String userAgent;

        public Builder() {
    	      // Empty
        }

        public Builder(GetEventsAuditEventDataIdentity defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.authType = defaults.authType;
    	      this.callerId = defaults.callerId;
    	      this.callerName = defaults.callerName;
    	      this.consoleSessionId = defaults.consoleSessionId;
    	      this.credentials = defaults.credentials;
    	      this.ipAddress = defaults.ipAddress;
    	      this.principalId = defaults.principalId;
    	      this.principalName = defaults.principalName;
    	      this.tenantId = defaults.tenantId;
    	      this.userAgent = defaults.userAgent;
        }

        public Builder authType(String authType) {
            this.authType = Objects.requireNonNull(authType);
            return this;
        }
        public Builder callerId(String callerId) {
            this.callerId = Objects.requireNonNull(callerId);
            return this;
        }
        public Builder callerName(String callerName) {
            this.callerName = Objects.requireNonNull(callerName);
            return this;
        }
        public Builder consoleSessionId(String consoleSessionId) {
            this.consoleSessionId = Objects.requireNonNull(consoleSessionId);
            return this;
        }
        public Builder credentials(String credentials) {
            this.credentials = Objects.requireNonNull(credentials);
            return this;
        }
        public Builder ipAddress(String ipAddress) {
            this.ipAddress = Objects.requireNonNull(ipAddress);
            return this;
        }
        public Builder principalId(String principalId) {
            this.principalId = Objects.requireNonNull(principalId);
            return this;
        }
        public Builder principalName(String principalName) {
            this.principalName = Objects.requireNonNull(principalName);
            return this;
        }
        public Builder tenantId(String tenantId) {
            this.tenantId = Objects.requireNonNull(tenantId);
            return this;
        }
        public Builder userAgent(String userAgent) {
            this.userAgent = Objects.requireNonNull(userAgent);
            return this;
        }        public GetEventsAuditEventDataIdentity build() {
            return new GetEventsAuditEventDataIdentity(authType, callerId, callerName, consoleSessionId, credentials, ipAddress, principalId, principalName, tenantId, userAgent);
        }
    }
}
