// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeploymentsDeploymentCollectionItemPlacement {
    /**
     * @return The availability domain of a placement.
     * 
     */
    private String availabilityDomain;
    /**
     * @return The fault domain of a placement.
     * 
     */
    private String faultDomain;

    private GetDeploymentsDeploymentCollectionItemPlacement() {}
    /**
     * @return The availability domain of a placement.
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The fault domain of a placement.
     * 
     */
    public String faultDomain() {
        return this.faultDomain;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsDeploymentCollectionItemPlacement defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String faultDomain;
        public Builder() {}
        public Builder(GetDeploymentsDeploymentCollectionItemPlacement defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.faultDomain = defaults.faultDomain;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionItemPlacement", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder faultDomain(String faultDomain) {
            if (faultDomain == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionItemPlacement", "faultDomain");
            }
            this.faultDomain = faultDomain;
            return this;
        }
        public GetDeploymentsDeploymentCollectionItemPlacement build() {
            final var _resultValue = new GetDeploymentsDeploymentCollectionItemPlacement();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.faultDomain = faultDomain;
            return _resultValue;
        }
    }
}
