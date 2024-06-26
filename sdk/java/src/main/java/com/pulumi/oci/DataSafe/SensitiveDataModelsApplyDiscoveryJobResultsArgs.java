// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class SensitiveDataModelsApplyDiscoveryJobResultsArgs extends com.pulumi.resources.ResourceArgs {

    public static final SensitiveDataModelsApplyDiscoveryJobResultsArgs Empty = new SensitiveDataModelsApplyDiscoveryJobResultsArgs();

    @Import(name="discoveryJobId", required=true)
    private Output<String> discoveryJobId;

    public Output<String> discoveryJobId() {
        return this.discoveryJobId;
    }

    @Import(name="sensitiveDataModelId", required=true)
    private Output<String> sensitiveDataModelId;

    public Output<String> sensitiveDataModelId() {
        return this.sensitiveDataModelId;
    }

    private SensitiveDataModelsApplyDiscoveryJobResultsArgs() {}

    private SensitiveDataModelsApplyDiscoveryJobResultsArgs(SensitiveDataModelsApplyDiscoveryJobResultsArgs $) {
        this.discoveryJobId = $.discoveryJobId;
        this.sensitiveDataModelId = $.sensitiveDataModelId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SensitiveDataModelsApplyDiscoveryJobResultsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SensitiveDataModelsApplyDiscoveryJobResultsArgs $;

        public Builder() {
            $ = new SensitiveDataModelsApplyDiscoveryJobResultsArgs();
        }

        public Builder(SensitiveDataModelsApplyDiscoveryJobResultsArgs defaults) {
            $ = new SensitiveDataModelsApplyDiscoveryJobResultsArgs(Objects.requireNonNull(defaults));
        }

        public Builder discoveryJobId(Output<String> discoveryJobId) {
            $.discoveryJobId = discoveryJobId;
            return this;
        }

        public Builder discoveryJobId(String discoveryJobId) {
            return discoveryJobId(Output.of(discoveryJobId));
        }

        public Builder sensitiveDataModelId(Output<String> sensitiveDataModelId) {
            $.sensitiveDataModelId = sensitiveDataModelId;
            return this;
        }

        public Builder sensitiveDataModelId(String sensitiveDataModelId) {
            return sensitiveDataModelId(Output.of(sensitiveDataModelId));
        }

        public SensitiveDataModelsApplyDiscoveryJobResultsArgs build() {
            if ($.discoveryJobId == null) {
                throw new MissingRequiredPropertyException("SensitiveDataModelsApplyDiscoveryJobResultsArgs", "discoveryJobId");
            }
            if ($.sensitiveDataModelId == null) {
                throw new MissingRequiredPropertyException("SensitiveDataModelsApplyDiscoveryJobResultsArgs", "sensitiveDataModelId");
            }
            return $;
        }
    }

}
