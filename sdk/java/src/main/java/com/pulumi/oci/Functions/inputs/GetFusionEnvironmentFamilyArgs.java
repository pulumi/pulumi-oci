// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetFusionEnvironmentFamilyArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFusionEnvironmentFamilyArgs Empty = new GetFusionEnvironmentFamilyArgs();

    /**
     * The unique identifier (OCID) of the FusionEnvironmentFamily.
     * 
     */
    @Import(name="fusionEnvironmentFamilyId", required=true)
    private Output<String> fusionEnvironmentFamilyId;

    /**
     * @return The unique identifier (OCID) of the FusionEnvironmentFamily.
     * 
     */
    public Output<String> fusionEnvironmentFamilyId() {
        return this.fusionEnvironmentFamilyId;
    }

    private GetFusionEnvironmentFamilyArgs() {}

    private GetFusionEnvironmentFamilyArgs(GetFusionEnvironmentFamilyArgs $) {
        this.fusionEnvironmentFamilyId = $.fusionEnvironmentFamilyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFusionEnvironmentFamilyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFusionEnvironmentFamilyArgs $;

        public Builder() {
            $ = new GetFusionEnvironmentFamilyArgs();
        }

        public Builder(GetFusionEnvironmentFamilyArgs defaults) {
            $ = new GetFusionEnvironmentFamilyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param fusionEnvironmentFamilyId The unique identifier (OCID) of the FusionEnvironmentFamily.
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentFamilyId(Output<String> fusionEnvironmentFamilyId) {
            $.fusionEnvironmentFamilyId = fusionEnvironmentFamilyId;
            return this;
        }

        /**
         * @param fusionEnvironmentFamilyId The unique identifier (OCID) of the FusionEnvironmentFamily.
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentFamilyId(String fusionEnvironmentFamilyId) {
            return fusionEnvironmentFamilyId(Output.of(fusionEnvironmentFamilyId));
        }

        public GetFusionEnvironmentFamilyArgs build() {
            $.fusionEnvironmentFamilyId = Objects.requireNonNull($.fusionEnvironmentFamilyId, "expected parameter 'fusionEnvironmentFamilyId' to be non-null");
            return $;
        }
    }

}