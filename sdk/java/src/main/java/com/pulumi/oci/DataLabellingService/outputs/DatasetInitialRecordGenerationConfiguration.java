// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataLabellingService.outputs;

import com.pulumi.core.annotations.CustomType;
import java.util.Objects;

@CustomType
public final class DatasetInitialRecordGenerationConfiguration {
    private DatasetInitialRecordGenerationConfiguration() {}

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DatasetInitialRecordGenerationConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        public Builder() {}
        public Builder(DatasetInitialRecordGenerationConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
        }

        public DatasetInitialRecordGenerationConfiguration build() {
            final var _resultValue = new DatasetInitialRecordGenerationConfiguration();
            return _resultValue;
        }
    }
}
