// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetFusionEnvironmentStatusArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFusionEnvironmentStatusArgs Empty = new GetFusionEnvironmentStatusArgs();

    /**
     * unique FusionEnvironment identifier
     * 
     */
    @Import(name="fusionEnvironmentId", required=true)
    private Output<String> fusionEnvironmentId;

    /**
     * @return unique FusionEnvironment identifier
     * 
     */
    public Output<String> fusionEnvironmentId() {
        return this.fusionEnvironmentId;
    }

    private GetFusionEnvironmentStatusArgs() {}

    private GetFusionEnvironmentStatusArgs(GetFusionEnvironmentStatusArgs $) {
        this.fusionEnvironmentId = $.fusionEnvironmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFusionEnvironmentStatusArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFusionEnvironmentStatusArgs $;

        public Builder() {
            $ = new GetFusionEnvironmentStatusArgs();
        }

        public Builder(GetFusionEnvironmentStatusArgs defaults) {
            $ = new GetFusionEnvironmentStatusArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param fusionEnvironmentId unique FusionEnvironment identifier
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentId(Output<String> fusionEnvironmentId) {
            $.fusionEnvironmentId = fusionEnvironmentId;
            return this;
        }

        /**
         * @param fusionEnvironmentId unique FusionEnvironment identifier
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentId(String fusionEnvironmentId) {
            return fusionEnvironmentId(Output.of(fusionEnvironmentId));
        }

        public GetFusionEnvironmentStatusArgs build() {
            $.fusionEnvironmentId = Objects.requireNonNull($.fusionEnvironmentId, "expected parameter 'fusionEnvironmentId' to be non-null");
            return $;
        }
    }

}