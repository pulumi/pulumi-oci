// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsCloudGateServer {
    /**
     * @return (Updatable) Hostname for the Server block
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private String hostName;
    /**
     * @return (Updatable) More nginx Settings. JSON encoded text block
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String nginxSettings;
    /**
     * @return (Updatable) Port for the Server Block
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    private Integer port;
    /**
     * @return (Updatable) Server Name for the Server Block
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    private @Nullable String serverId;
    /**
     * @return (Updatable) SSL flag for the Server Block
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    private Boolean ssl;

    private DomainsCloudGateServer() {}
    /**
     * @return (Updatable) Hostname for the Server block
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public String hostName() {
        return this.hostName;
    }
    /**
     * @return (Updatable) More nginx Settings. JSON encoded text block
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> nginxSettings() {
        return Optional.ofNullable(this.nginxSettings);
    }
    /**
     * @return (Updatable) Port for the Server Block
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return (Updatable) Server Name for the Server Block
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<String> serverId() {
        return Optional.ofNullable(this.serverId);
    }
    /**
     * @return (Updatable) SSL flag for the Server Block
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Boolean ssl() {
        return this.ssl;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsCloudGateServer defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hostName;
        private @Nullable String nginxSettings;
        private Integer port;
        private @Nullable String serverId;
        private Boolean ssl;
        public Builder() {}
        public Builder(DomainsCloudGateServer defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hostName = defaults.hostName;
    	      this.nginxSettings = defaults.nginxSettings;
    	      this.port = defaults.port;
    	      this.serverId = defaults.serverId;
    	      this.ssl = defaults.ssl;
        }

        @CustomType.Setter
        public Builder hostName(String hostName) {
            if (hostName == null) {
              throw new MissingRequiredPropertyException("DomainsCloudGateServer", "hostName");
            }
            this.hostName = hostName;
            return this;
        }
        @CustomType.Setter
        public Builder nginxSettings(@Nullable String nginxSettings) {

            this.nginxSettings = nginxSettings;
            return this;
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            if (port == null) {
              throw new MissingRequiredPropertyException("DomainsCloudGateServer", "port");
            }
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder serverId(@Nullable String serverId) {

            this.serverId = serverId;
            return this;
        }
        @CustomType.Setter
        public Builder ssl(Boolean ssl) {
            if (ssl == null) {
              throw new MissingRequiredPropertyException("DomainsCloudGateServer", "ssl");
            }
            this.ssl = ssl;
            return this;
        }
        public DomainsCloudGateServer build() {
            final var _resultValue = new DomainsCloudGateServer();
            _resultValue.hostName = hostName;
            _resultValue.nginxSettings = nginxSettings;
            _resultValue.port = port;
            _resultValue.serverId = serverId;
            _resultValue.ssl = ssl;
            return _resultValue;
        }
    }
}
