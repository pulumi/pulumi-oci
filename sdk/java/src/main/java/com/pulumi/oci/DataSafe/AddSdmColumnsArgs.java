// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class AddSdmColumnsArgs extends com.pulumi.resources.ResourceArgs {

    public static final AddSdmColumnsArgs Empty = new AddSdmColumnsArgs();

    @Import(name="maskingPolicyId", required=true)
    private Output<String> maskingPolicyId;

    public Output<String> maskingPolicyId() {
        return this.maskingPolicyId;
    }

    private AddSdmColumnsArgs() {}

    private AddSdmColumnsArgs(AddSdmColumnsArgs $) {
        this.maskingPolicyId = $.maskingPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AddSdmColumnsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AddSdmColumnsArgs $;

        public Builder() {
            $ = new AddSdmColumnsArgs();
        }

        public Builder(AddSdmColumnsArgs defaults) {
            $ = new AddSdmColumnsArgs(Objects.requireNonNull(defaults));
        }

        public Builder maskingPolicyId(Output<String> maskingPolicyId) {
            $.maskingPolicyId = maskingPolicyId;
            return this;
        }

        public Builder maskingPolicyId(String maskingPolicyId) {
            return maskingPolicyId(Output.of(maskingPolicyId));
        }

        public AddSdmColumnsArgs build() {
            if ($.maskingPolicyId == null) {
                throw new MissingRequiredPropertyException("AddSdmColumnsArgs", "maskingPolicyId");
            }
            return $;
        }
    }

}
