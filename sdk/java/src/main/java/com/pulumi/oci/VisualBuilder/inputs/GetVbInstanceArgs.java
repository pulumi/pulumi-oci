// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.VisualBuilder.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetVbInstanceArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVbInstanceArgs Empty = new GetVbInstanceArgs();

    /**
     * Unique Vb Instance identifier.
     * 
     */
    @Import(name="vbInstanceId", required=true)
    private Output<String> vbInstanceId;

    /**
     * @return Unique Vb Instance identifier.
     * 
     */
    public Output<String> vbInstanceId() {
        return this.vbInstanceId;
    }

    private GetVbInstanceArgs() {}

    private GetVbInstanceArgs(GetVbInstanceArgs $) {
        this.vbInstanceId = $.vbInstanceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVbInstanceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVbInstanceArgs $;

        public Builder() {
            $ = new GetVbInstanceArgs();
        }

        public Builder(GetVbInstanceArgs defaults) {
            $ = new GetVbInstanceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param vbInstanceId Unique Vb Instance identifier.
         * 
         * @return builder
         * 
         */
        public Builder vbInstanceId(Output<String> vbInstanceId) {
            $.vbInstanceId = vbInstanceId;
            return this;
        }

        /**
         * @param vbInstanceId Unique Vb Instance identifier.
         * 
         * @return builder
         * 
         */
        public Builder vbInstanceId(String vbInstanceId) {
            return vbInstanceId(Output.of(vbInstanceId));
        }

        public GetVbInstanceArgs build() {
            $.vbInstanceId = Objects.requireNonNull($.vbInstanceId, "expected parameter 'vbInstanceId' to be non-null");
            return $;
        }
    }

}