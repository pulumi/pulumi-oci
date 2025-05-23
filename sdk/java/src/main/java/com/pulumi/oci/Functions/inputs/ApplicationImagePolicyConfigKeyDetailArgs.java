// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class ApplicationImagePolicyConfigKeyDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final ApplicationImagePolicyConfigKeyDetailArgs Empty = new ApplicationImagePolicyConfigKeyDetailArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s of the KMS key that will be used to verify the image signature.
     * 
     */
    @Import(name="kmsKeyId", required=true)
    private Output<String> kmsKeyId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s of the KMS key that will be used to verify the image signature.
     * 
     */
    public Output<String> kmsKeyId() {
        return this.kmsKeyId;
    }

    private ApplicationImagePolicyConfigKeyDetailArgs() {}

    private ApplicationImagePolicyConfigKeyDetailArgs(ApplicationImagePolicyConfigKeyDetailArgs $) {
        this.kmsKeyId = $.kmsKeyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ApplicationImagePolicyConfigKeyDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ApplicationImagePolicyConfigKeyDetailArgs $;

        public Builder() {
            $ = new ApplicationImagePolicyConfigKeyDetailArgs();
        }

        public Builder(ApplicationImagePolicyConfigKeyDetailArgs defaults) {
            $ = new ApplicationImagePolicyConfigKeyDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param kmsKeyId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s of the KMS key that will be used to verify the image signature.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(Output<String> kmsKeyId) {
            $.kmsKeyId = kmsKeyId;
            return this;
        }

        /**
         * @param kmsKeyId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s of the KMS key that will be used to verify the image signature.
         * 
         * @return builder
         * 
         */
        public Builder kmsKeyId(String kmsKeyId) {
            return kmsKeyId(Output.of(kmsKeyId));
        }

        public ApplicationImagePolicyConfigKeyDetailArgs build() {
            if ($.kmsKeyId == null) {
                throw new MissingRequiredPropertyException("ApplicationImagePolicyConfigKeyDetailArgs", "kmsKeyId");
            }
            return $;
        }
    }

}
