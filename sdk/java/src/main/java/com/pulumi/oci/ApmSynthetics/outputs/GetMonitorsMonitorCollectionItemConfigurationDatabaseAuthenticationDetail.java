// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApmSynthetics.outputs.GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetailPassword;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetail {
    /**
     * @return Password.
     * 
     */
    private List<GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetailPassword> passwords;
    /**
     * @return Username for authentication.
     * 
     */
    private String username;

    private GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetail() {}
    /**
     * @return Password.
     * 
     */
    public List<GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetailPassword> passwords() {
        return this.passwords;
    }
    /**
     * @return Username for authentication.
     * 
     */
    public String username() {
        return this.username;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetailPassword> passwords;
        private String username;
        public Builder() {}
        public Builder(GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.passwords = defaults.passwords;
    	      this.username = defaults.username;
        }

        @CustomType.Setter
        public Builder passwords(List<GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetailPassword> passwords) {
            if (passwords == null) {
              throw new MissingRequiredPropertyException("GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetail", "passwords");
            }
            this.passwords = passwords;
            return this;
        }
        public Builder passwords(GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetailPassword... passwords) {
            return passwords(List.of(passwords));
        }
        @CustomType.Setter
        public Builder username(String username) {
            if (username == null) {
              throw new MissingRequiredPropertyException("GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetail", "username");
            }
            this.username = username;
            return this;
        }
        public GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetail build() {
            final var _resultValue = new GetMonitorsMonitorCollectionItemConfigurationDatabaseAuthenticationDetail();
            _resultValue.passwords = passwords;
            _resultValue.username = username;
            return _resultValue;
        }
    }
}
