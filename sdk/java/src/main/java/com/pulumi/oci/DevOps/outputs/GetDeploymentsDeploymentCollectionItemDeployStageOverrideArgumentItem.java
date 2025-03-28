// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeploymentsDeploymentCollectionItemDeployStageOverrideArgumentItem {
    /**
     * @return The OCID of the stage.
     * 
     */
    private String deployStageId;
    /**
     * @return Name of the step.
     * 
     */
    private String name;
    /**
     * @return value of the argument.
     * 
     */
    private String value;

    private GetDeploymentsDeploymentCollectionItemDeployStageOverrideArgumentItem() {}
    /**
     * @return The OCID of the stage.
     * 
     */
    public String deployStageId() {
        return this.deployStageId;
    }
    /**
     * @return Name of the step.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return value of the argument.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsDeploymentCollectionItemDeployStageOverrideArgumentItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String deployStageId;
        private String name;
        private String value;
        public Builder() {}
        public Builder(GetDeploymentsDeploymentCollectionItemDeployStageOverrideArgumentItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.deployStageId = defaults.deployStageId;
    	      this.name = defaults.name;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder deployStageId(String deployStageId) {
            if (deployStageId == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionItemDeployStageOverrideArgumentItem", "deployStageId");
            }
            this.deployStageId = deployStageId;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionItemDeployStageOverrideArgumentItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionItemDeployStageOverrideArgumentItem", "value");
            }
            this.value = value;
            return this;
        }
        public GetDeploymentsDeploymentCollectionItemDeployStageOverrideArgumentItem build() {
            final var _resultValue = new GetDeploymentsDeploymentCollectionItemDeployStageOverrideArgumentItem();
            _resultValue.deployStageId = deployStageId;
            _resultValue.name = name;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
