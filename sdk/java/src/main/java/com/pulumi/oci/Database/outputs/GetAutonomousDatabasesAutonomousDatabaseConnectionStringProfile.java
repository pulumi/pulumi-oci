// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile {
    /**
     * @return Consumer group used by the connection.
     * 
     */
    private String consumerGroup;
    /**
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    private String displayName;
    /**
     * @return Host format used in connection string.
     * 
     */
    private String hostFormat;
    private Boolean isRegional;
    /**
     * @return Protocol used by the connection.
     * 
     */
    private String protocol;
    /**
     * @return Specifies whether the listener performs a direct hand-off of the session, or redirects the session. In RAC deployments where SCAN is used, sessions are redirected to a Node VIP. Use `DIRECT` for direct hand-offs. Use `REDIRECT` to redirect the session.
     * 
     */
    private String sessionMode;
    /**
     * @return Specifies whether the connection string is using the long (`LONG`), Easy Connect (`EZCONNECT`), or Easy Connect Plus (`EZCONNECTPLUS`) format. Autonomous Databases on shared Exadata infrastructure always use the long format.
     * 
     */
    private String syntaxFormat;
    /**
     * @return Specifies whether the TLS handshake is using one-way (`SERVER`) or mutual (`MUTUAL`) authentication.
     * 
     */
    private String tlsAuthentication;
    /**
     * @return Connection string value.
     * 
     */
    private String value;

    private GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile() {}
    /**
     * @return Consumer group used by the connection.
     * 
     */
    public String consumerGroup() {
        return this.consumerGroup;
    }
    /**
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Host format used in connection string.
     * 
     */
    public String hostFormat() {
        return this.hostFormat;
    }
    public Boolean isRegional() {
        return this.isRegional;
    }
    /**
     * @return Protocol used by the connection.
     * 
     */
    public String protocol() {
        return this.protocol;
    }
    /**
     * @return Specifies whether the listener performs a direct hand-off of the session, or redirects the session. In RAC deployments where SCAN is used, sessions are redirected to a Node VIP. Use `DIRECT` for direct hand-offs. Use `REDIRECT` to redirect the session.
     * 
     */
    public String sessionMode() {
        return this.sessionMode;
    }
    /**
     * @return Specifies whether the connection string is using the long (`LONG`), Easy Connect (`EZCONNECT`), or Easy Connect Plus (`EZCONNECTPLUS`) format. Autonomous Databases on shared Exadata infrastructure always use the long format.
     * 
     */
    public String syntaxFormat() {
        return this.syntaxFormat;
    }
    /**
     * @return Specifies whether the TLS handshake is using one-way (`SERVER`) or mutual (`MUTUAL`) authentication.
     * 
     */
    public String tlsAuthentication() {
        return this.tlsAuthentication;
    }
    /**
     * @return Connection string value.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String consumerGroup;
        private String displayName;
        private String hostFormat;
        private Boolean isRegional;
        private String protocol;
        private String sessionMode;
        private String syntaxFormat;
        private String tlsAuthentication;
        private String value;
        public Builder() {}
        public Builder(GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.consumerGroup = defaults.consumerGroup;
    	      this.displayName = defaults.displayName;
    	      this.hostFormat = defaults.hostFormat;
    	      this.isRegional = defaults.isRegional;
    	      this.protocol = defaults.protocol;
    	      this.sessionMode = defaults.sessionMode;
    	      this.syntaxFormat = defaults.syntaxFormat;
    	      this.tlsAuthentication = defaults.tlsAuthentication;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder consumerGroup(String consumerGroup) {
            if (consumerGroup == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile", "consumerGroup");
            }
            this.consumerGroup = consumerGroup;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder hostFormat(String hostFormat) {
            if (hostFormat == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile", "hostFormat");
            }
            this.hostFormat = hostFormat;
            return this;
        }
        @CustomType.Setter
        public Builder isRegional(Boolean isRegional) {
            if (isRegional == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile", "isRegional");
            }
            this.isRegional = isRegional;
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            if (protocol == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile", "protocol");
            }
            this.protocol = protocol;
            return this;
        }
        @CustomType.Setter
        public Builder sessionMode(String sessionMode) {
            if (sessionMode == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile", "sessionMode");
            }
            this.sessionMode = sessionMode;
            return this;
        }
        @CustomType.Setter
        public Builder syntaxFormat(String syntaxFormat) {
            if (syntaxFormat == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile", "syntaxFormat");
            }
            this.syntaxFormat = syntaxFormat;
            return this;
        }
        @CustomType.Setter
        public Builder tlsAuthentication(String tlsAuthentication) {
            if (tlsAuthentication == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile", "tlsAuthentication");
            }
            this.tlsAuthentication = tlsAuthentication;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile", "value");
            }
            this.value = value;
            return this;
        }
        public GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile build() {
            final var _resultValue = new GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile();
            _resultValue.consumerGroup = consumerGroup;
            _resultValue.displayName = displayName;
            _resultValue.hostFormat = hostFormat;
            _resultValue.isRegional = isRegional;
            _resultValue.protocol = protocol;
            _resultValue.sessionMode = sessionMode;
            _resultValue.syntaxFormat = syntaxFormat;
            _resultValue.tlsAuthentication = tlsAuthentication;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
