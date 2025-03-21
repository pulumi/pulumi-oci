// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetFleetCredentialsFleetCredentialCollectionItemEntitySpecificVariable;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetFleetCredentialsFleetCredentialCollectionItemEntitySpecific {
    /**
     * @return A filter to return only resources whose credentialLevel matches the given credentialLevel.
     * 
     */
    private String credentialLevel;
    /**
     * @return Resource Identifier
     * 
     */
    private String resourceId;
    /**
     * @return A filter to return only resources whose target matches the given target name.
     * 
     */
    private String target;
    /**
     * @return List of fleet credential variables.
     * 
     */
    private List<GetFleetCredentialsFleetCredentialCollectionItemEntitySpecificVariable> variables;

    private GetFleetCredentialsFleetCredentialCollectionItemEntitySpecific() {}
    /**
     * @return A filter to return only resources whose credentialLevel matches the given credentialLevel.
     * 
     */
    public String credentialLevel() {
        return this.credentialLevel;
    }
    /**
     * @return Resource Identifier
     * 
     */
    public String resourceId() {
        return this.resourceId;
    }
    /**
     * @return A filter to return only resources whose target matches the given target name.
     * 
     */
    public String target() {
        return this.target;
    }
    /**
     * @return List of fleet credential variables.
     * 
     */
    public List<GetFleetCredentialsFleetCredentialCollectionItemEntitySpecificVariable> variables() {
        return this.variables;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetCredentialsFleetCredentialCollectionItemEntitySpecific defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String credentialLevel;
        private String resourceId;
        private String target;
        private List<GetFleetCredentialsFleetCredentialCollectionItemEntitySpecificVariable> variables;
        public Builder() {}
        public Builder(GetFleetCredentialsFleetCredentialCollectionItemEntitySpecific defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.credentialLevel = defaults.credentialLevel;
    	      this.resourceId = defaults.resourceId;
    	      this.target = defaults.target;
    	      this.variables = defaults.variables;
        }

        @CustomType.Setter
        public Builder credentialLevel(String credentialLevel) {
            if (credentialLevel == null) {
              throw new MissingRequiredPropertyException("GetFleetCredentialsFleetCredentialCollectionItemEntitySpecific", "credentialLevel");
            }
            this.credentialLevel = credentialLevel;
            return this;
        }
        @CustomType.Setter
        public Builder resourceId(String resourceId) {
            if (resourceId == null) {
              throw new MissingRequiredPropertyException("GetFleetCredentialsFleetCredentialCollectionItemEntitySpecific", "resourceId");
            }
            this.resourceId = resourceId;
            return this;
        }
        @CustomType.Setter
        public Builder target(String target) {
            if (target == null) {
              throw new MissingRequiredPropertyException("GetFleetCredentialsFleetCredentialCollectionItemEntitySpecific", "target");
            }
            this.target = target;
            return this;
        }
        @CustomType.Setter
        public Builder variables(List<GetFleetCredentialsFleetCredentialCollectionItemEntitySpecificVariable> variables) {
            if (variables == null) {
              throw new MissingRequiredPropertyException("GetFleetCredentialsFleetCredentialCollectionItemEntitySpecific", "variables");
            }
            this.variables = variables;
            return this;
        }
        public Builder variables(GetFleetCredentialsFleetCredentialCollectionItemEntitySpecificVariable... variables) {
            return variables(List.of(variables));
        }
        public GetFleetCredentialsFleetCredentialCollectionItemEntitySpecific build() {
            final var _resultValue = new GetFleetCredentialsFleetCredentialCollectionItemEntitySpecific();
            _resultValue.credentialLevel = credentialLevel;
            _resultValue.resourceId = resourceId;
            _resultValue.target = target;
            _resultValue.variables = variables;
            return _resultValue;
        }
    }
}
