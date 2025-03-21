// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetSensitiveTypeArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSensitiveTypeArgs Empty = new GetSensitiveTypeArgs();

    /**
     * The OCID of the sensitive type.
     * 
     */
    @Import(name="sensitiveTypeId", required=true)
    private Output<String> sensitiveTypeId;

    /**
     * @return The OCID of the sensitive type.
     * 
     */
    public Output<String> sensitiveTypeId() {
        return this.sensitiveTypeId;
    }

    private GetSensitiveTypeArgs() {}

    private GetSensitiveTypeArgs(GetSensitiveTypeArgs $) {
        this.sensitiveTypeId = $.sensitiveTypeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSensitiveTypeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSensitiveTypeArgs $;

        public Builder() {
            $ = new GetSensitiveTypeArgs();
        }

        public Builder(GetSensitiveTypeArgs defaults) {
            $ = new GetSensitiveTypeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param sensitiveTypeId The OCID of the sensitive type.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveTypeId(Output<String> sensitiveTypeId) {
            $.sensitiveTypeId = sensitiveTypeId;
            return this;
        }

        /**
         * @param sensitiveTypeId The OCID of the sensitive type.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveTypeId(String sensitiveTypeId) {
            return sensitiveTypeId(Output.of(sensitiveTypeId));
        }

        public GetSensitiveTypeArgs build() {
            if ($.sensitiveTypeId == null) {
                throw new MissingRequiredPropertyException("GetSensitiveTypeArgs", "sensitiveTypeId");
            }
            return $;
        }
    }

}
