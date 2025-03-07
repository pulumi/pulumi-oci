// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class MaskDataArgs extends com.pulumi.resources.ResourceArgs {

    public static final MaskDataArgs Empty = new MaskDataArgs();

    @Import(name="maskingPolicyId", required=true)
    private Output<String> maskingPolicyId;

    public Output<String> maskingPolicyId() {
        return this.maskingPolicyId;
    }

    @Import(name="targetId", required=true)
    private Output<String> targetId;

    public Output<String> targetId() {
        return this.targetId;
    }

    private MaskDataArgs() {}

    private MaskDataArgs(MaskDataArgs $) {
        this.maskingPolicyId = $.maskingPolicyId;
        this.targetId = $.targetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MaskDataArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MaskDataArgs $;

        public Builder() {
            $ = new MaskDataArgs();
        }

        public Builder(MaskDataArgs defaults) {
            $ = new MaskDataArgs(Objects.requireNonNull(defaults));
        }

        public Builder maskingPolicyId(Output<String> maskingPolicyId) {
            $.maskingPolicyId = maskingPolicyId;
            return this;
        }

        public Builder maskingPolicyId(String maskingPolicyId) {
            return maskingPolicyId(Output.of(maskingPolicyId));
        }

        public Builder targetId(Output<String> targetId) {
            $.targetId = targetId;
            return this;
        }

        public Builder targetId(String targetId) {
            return targetId(Output.of(targetId));
        }

        public MaskDataArgs build() {
            if ($.maskingPolicyId == null) {
                throw new MissingRequiredPropertyException("MaskDataArgs", "maskingPolicyId");
            }
            if ($.targetId == null) {
                throw new MissingRequiredPropertyException("MaskDataArgs", "targetId");
            }
            return $;
        }
    }

}
