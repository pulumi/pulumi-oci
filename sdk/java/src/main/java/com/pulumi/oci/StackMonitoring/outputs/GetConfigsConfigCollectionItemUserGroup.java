// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetConfigsConfigCollectionItemUserGroup {
    /**
     * @return Identity domain name
     * 
     */
    private String domain;
    /**
     * @return Name of user Group
     * 
     */
    private String name;
    /**
     * @return Role assigned to user group in context of Stack Monitoring service. Access role can be for example: ADMINISTRATOR, OPERATOR, VIEWER, any other access role
     * 
     */
    private String stackMonitoringRole;

    private GetConfigsConfigCollectionItemUserGroup() {}
    /**
     * @return Identity domain name
     * 
     */
    public String domain() {
        return this.domain;
    }
    /**
     * @return Name of user Group
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Role assigned to user group in context of Stack Monitoring service. Access role can be for example: ADMINISTRATOR, OPERATOR, VIEWER, any other access role
     * 
     */
    public String stackMonitoringRole() {
        return this.stackMonitoringRole;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConfigsConfigCollectionItemUserGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String domain;
        private String name;
        private String stackMonitoringRole;
        public Builder() {}
        public Builder(GetConfigsConfigCollectionItemUserGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.domain = defaults.domain;
    	      this.name = defaults.name;
    	      this.stackMonitoringRole = defaults.stackMonitoringRole;
        }

        @CustomType.Setter
        public Builder domain(String domain) {
            if (domain == null) {
              throw new MissingRequiredPropertyException("GetConfigsConfigCollectionItemUserGroup", "domain");
            }
            this.domain = domain;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetConfigsConfigCollectionItemUserGroup", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder stackMonitoringRole(String stackMonitoringRole) {
            if (stackMonitoringRole == null) {
              throw new MissingRequiredPropertyException("GetConfigsConfigCollectionItemUserGroup", "stackMonitoringRole");
            }
            this.stackMonitoringRole = stackMonitoringRole;
            return this;
        }
        public GetConfigsConfigCollectionItemUserGroup build() {
            final var _resultValue = new GetConfigsConfigCollectionItemUserGroup();
            _resultValue.domain = domain;
            _resultValue.name = name;
            _resultValue.stackMonitoringRole = stackMonitoringRole;
            return _resultValue;
        }
    }
}
