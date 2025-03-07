// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAssetsAssetCollectionItemComputeNvdimmController {
    /**
     * @return Bus number.
     * 
     */
    private Integer busNumber;
    /**
     * @return Provides a label and summary information for the device.
     * 
     */
    private String label;

    private GetAssetsAssetCollectionItemComputeNvdimmController() {}
    /**
     * @return Bus number.
     * 
     */
    public Integer busNumber() {
        return this.busNumber;
    }
    /**
     * @return Provides a label and summary information for the device.
     * 
     */
    public String label() {
        return this.label;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAssetsAssetCollectionItemComputeNvdimmController defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer busNumber;
        private String label;
        public Builder() {}
        public Builder(GetAssetsAssetCollectionItemComputeNvdimmController defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.busNumber = defaults.busNumber;
    	      this.label = defaults.label;
        }

        @CustomType.Setter
        public Builder busNumber(Integer busNumber) {
            if (busNumber == null) {
              throw new MissingRequiredPropertyException("GetAssetsAssetCollectionItemComputeNvdimmController", "busNumber");
            }
            this.busNumber = busNumber;
            return this;
        }
        @CustomType.Setter
        public Builder label(String label) {
            if (label == null) {
              throw new MissingRequiredPropertyException("GetAssetsAssetCollectionItemComputeNvdimmController", "label");
            }
            this.label = label;
            return this;
        }
        public GetAssetsAssetCollectionItemComputeNvdimmController build() {
            final var _resultValue = new GetAssetsAssetCollectionItemComputeNvdimmController();
            _resultValue.busNumber = busNumber;
            _resultValue.label = label;
            return _resultValue;
        }
    }
}
