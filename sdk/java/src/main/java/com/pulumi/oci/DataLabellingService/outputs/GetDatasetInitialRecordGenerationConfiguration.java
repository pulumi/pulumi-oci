// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataLabellingService.outputs;

import com.pulumi.core.annotations.CustomType;
import java.util.Objects;

@CustomType
public final class GetDatasetInitialRecordGenerationConfiguration {
    @CustomType.Constructor
    private GetDatasetInitialRecordGenerationConfiguration() {
    }


    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatasetInitialRecordGenerationConfiguration defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {

        public Builder() {
    	      // Empty
        }

        public Builder(GetDatasetInitialRecordGenerationConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
        }
        public GetDatasetInitialRecordGenerationConfiguration build() {
            return new GetDatasetInitialRecordGenerationConfiguration();
        }
    }
}
