// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseTools.outputs.GetDatabaseToolsConnectionProxyClientUserPassword;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDatabaseToolsConnectionProxyClient {
    /**
     * @return The proxy authentication type.
     * 
     */
    private String proxyAuthenticationType;
    /**
     * @return A list of database roles for the client. These roles are enabled if the proxy is authorized to use the roles on behalf of the client.
     * 
     */
    private List<String> roles;
    /**
     * @return The database user name.
     * 
     */
    private String userName;
    /**
     * @return The user password.
     * 
     */
    private List<GetDatabaseToolsConnectionProxyClientUserPassword> userPasswords;

    private GetDatabaseToolsConnectionProxyClient() {}
    /**
     * @return The proxy authentication type.
     * 
     */
    public String proxyAuthenticationType() {
        return this.proxyAuthenticationType;
    }
    /**
     * @return A list of database roles for the client. These roles are enabled if the proxy is authorized to use the roles on behalf of the client.
     * 
     */
    public List<String> roles() {
        return this.roles;
    }
    /**
     * @return The database user name.
     * 
     */
    public String userName() {
        return this.userName;
    }
    /**
     * @return The user password.
     * 
     */
    public List<GetDatabaseToolsConnectionProxyClientUserPassword> userPasswords() {
        return this.userPasswords;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseToolsConnectionProxyClient defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String proxyAuthenticationType;
        private List<String> roles;
        private String userName;
        private List<GetDatabaseToolsConnectionProxyClientUserPassword> userPasswords;
        public Builder() {}
        public Builder(GetDatabaseToolsConnectionProxyClient defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.proxyAuthenticationType = defaults.proxyAuthenticationType;
    	      this.roles = defaults.roles;
    	      this.userName = defaults.userName;
    	      this.userPasswords = defaults.userPasswords;
        }

        @CustomType.Setter
        public Builder proxyAuthenticationType(String proxyAuthenticationType) {
            if (proxyAuthenticationType == null) {
              throw new MissingRequiredPropertyException("GetDatabaseToolsConnectionProxyClient", "proxyAuthenticationType");
            }
            this.proxyAuthenticationType = proxyAuthenticationType;
            return this;
        }
        @CustomType.Setter
        public Builder roles(List<String> roles) {
            if (roles == null) {
              throw new MissingRequiredPropertyException("GetDatabaseToolsConnectionProxyClient", "roles");
            }
            this.roles = roles;
            return this;
        }
        public Builder roles(String... roles) {
            return roles(List.of(roles));
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            if (userName == null) {
              throw new MissingRequiredPropertyException("GetDatabaseToolsConnectionProxyClient", "userName");
            }
            this.userName = userName;
            return this;
        }
        @CustomType.Setter
        public Builder userPasswords(List<GetDatabaseToolsConnectionProxyClientUserPassword> userPasswords) {
            if (userPasswords == null) {
              throw new MissingRequiredPropertyException("GetDatabaseToolsConnectionProxyClient", "userPasswords");
            }
            this.userPasswords = userPasswords;
            return this;
        }
        public Builder userPasswords(GetDatabaseToolsConnectionProxyClientUserPassword... userPasswords) {
            return userPasswords(List.of(userPasswords));
        }
        public GetDatabaseToolsConnectionProxyClient build() {
            final var _resultValue = new GetDatabaseToolsConnectionProxyClient();
            _resultValue.proxyAuthenticationType = proxyAuthenticationType;
            _resultValue.roles = roles;
            _resultValue.userName = userName;
            _resultValue.userPasswords = userPasswords;
            return _resultValue;
        }
    }
}
