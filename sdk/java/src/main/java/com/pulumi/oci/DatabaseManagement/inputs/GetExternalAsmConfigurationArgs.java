// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetExternalAsmConfigurationArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetExternalAsmConfigurationArgs Empty = new GetExternalAsmConfigurationArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
     * 
     */
    @Import(name="externalAsmId", required=true)
    private Output<String> externalAsmId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
     * 
     */
    public Output<String> externalAsmId() {
        return this.externalAsmId;
    }

    /**
     * The OCID of the Named Credential.
     * 
     */
    @Import(name="opcNamedCredentialId")
    private @Nullable Output<String> opcNamedCredentialId;

    /**
     * @return The OCID of the Named Credential.
     * 
     */
    public Optional<Output<String>> opcNamedCredentialId() {
        return Optional.ofNullable(this.opcNamedCredentialId);
    }

    private GetExternalAsmConfigurationArgs() {}

    private GetExternalAsmConfigurationArgs(GetExternalAsmConfigurationArgs $) {
        this.externalAsmId = $.externalAsmId;
        this.opcNamedCredentialId = $.opcNamedCredentialId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetExternalAsmConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetExternalAsmConfigurationArgs $;

        public Builder() {
            $ = new GetExternalAsmConfigurationArgs();
        }

        public Builder(GetExternalAsmConfigurationArgs defaults) {
            $ = new GetExternalAsmConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param externalAsmId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
         * 
         * @return builder
         * 
         */
        public Builder externalAsmId(Output<String> externalAsmId) {
            $.externalAsmId = externalAsmId;
            return this;
        }

        /**
         * @param externalAsmId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
         * 
         * @return builder
         * 
         */
        public Builder externalAsmId(String externalAsmId) {
            return externalAsmId(Output.of(externalAsmId));
        }

        /**
         * @param opcNamedCredentialId The OCID of the Named Credential.
         * 
         * @return builder
         * 
         */
        public Builder opcNamedCredentialId(@Nullable Output<String> opcNamedCredentialId) {
            $.opcNamedCredentialId = opcNamedCredentialId;
            return this;
        }

        /**
         * @param opcNamedCredentialId The OCID of the Named Credential.
         * 
         * @return builder
         * 
         */
        public Builder opcNamedCredentialId(String opcNamedCredentialId) {
            return opcNamedCredentialId(Output.of(opcNamedCredentialId));
        }

        public GetExternalAsmConfigurationArgs build() {
            if ($.externalAsmId == null) {
                throw new MissingRequiredPropertyException("GetExternalAsmConfigurationArgs", "externalAsmId");
            }
            return $;
        }
    }

}
