// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VirtualServiceMtlsArgs extends com.pulumi.resources.ResourceArgs {

    public static final VirtualServiceMtlsArgs Empty = new VirtualServiceMtlsArgs();

    /**
     * The OCID of the certificate resource that will be used for mTLS authentication with other virtual services in the mesh.
     * 
     */
    @Import(name="certificateId")
    private @Nullable Output<String> certificateId;

    /**
     * @return The OCID of the certificate resource that will be used for mTLS authentication with other virtual services in the mesh.
     * 
     */
    public Optional<Output<String>> certificateId() {
        return Optional.ofNullable(this.certificateId);
    }

    /**
     * (Updatable) The number of days the mTLS certificate is valid.  This value should be less than the Maximum Validity Duration  for Certificates (Days) setting on the Certificate Authority associated with this Mesh.  The certificate will be automatically renewed after 2/3 of the validity period, so a certificate with a maximum validity of 45 days will be renewed every 30 days.
     * 
     */
    @Import(name="maximumValidity")
    private @Nullable Output<Integer> maximumValidity;

    /**
     * @return (Updatable) The number of days the mTLS certificate is valid.  This value should be less than the Maximum Validity Duration  for Certificates (Days) setting on the Certificate Authority associated with this Mesh.  The certificate will be automatically renewed after 2/3 of the validity period, so a certificate with a maximum validity of 45 days will be renewed every 30 days.
     * 
     */
    public Optional<Output<Integer>> maximumValidity() {
        return Optional.ofNullable(this.maximumValidity);
    }

    /**
     * (Updatable) DISABLED: Connection is not tunneled. PERMISSIVE: Connection can be either plaintext or an mTLS tunnel. STRICT: Connection is an mTLS tunnel.  Clients without a valid certificate will be rejected.
     * 
     */
    @Import(name="mode", required=true)
    private Output<String> mode;

    /**
     * @return (Updatable) DISABLED: Connection is not tunneled. PERMISSIVE: Connection can be either plaintext or an mTLS tunnel. STRICT: Connection is an mTLS tunnel.  Clients without a valid certificate will be rejected.
     * 
     */
    public Output<String> mode() {
        return this.mode;
    }

    private VirtualServiceMtlsArgs() {}

    private VirtualServiceMtlsArgs(VirtualServiceMtlsArgs $) {
        this.certificateId = $.certificateId;
        this.maximumValidity = $.maximumValidity;
        this.mode = $.mode;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VirtualServiceMtlsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VirtualServiceMtlsArgs $;

        public Builder() {
            $ = new VirtualServiceMtlsArgs();
        }

        public Builder(VirtualServiceMtlsArgs defaults) {
            $ = new VirtualServiceMtlsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param certificateId The OCID of the certificate resource that will be used for mTLS authentication with other virtual services in the mesh.
         * 
         * @return builder
         * 
         */
        public Builder certificateId(@Nullable Output<String> certificateId) {
            $.certificateId = certificateId;
            return this;
        }

        /**
         * @param certificateId The OCID of the certificate resource that will be used for mTLS authentication with other virtual services in the mesh.
         * 
         * @return builder
         * 
         */
        public Builder certificateId(String certificateId) {
            return certificateId(Output.of(certificateId));
        }

        /**
         * @param maximumValidity (Updatable) The number of days the mTLS certificate is valid.  This value should be less than the Maximum Validity Duration  for Certificates (Days) setting on the Certificate Authority associated with this Mesh.  The certificate will be automatically renewed after 2/3 of the validity period, so a certificate with a maximum validity of 45 days will be renewed every 30 days.
         * 
         * @return builder
         * 
         */
        public Builder maximumValidity(@Nullable Output<Integer> maximumValidity) {
            $.maximumValidity = maximumValidity;
            return this;
        }

        /**
         * @param maximumValidity (Updatable) The number of days the mTLS certificate is valid.  This value should be less than the Maximum Validity Duration  for Certificates (Days) setting on the Certificate Authority associated with this Mesh.  The certificate will be automatically renewed after 2/3 of the validity period, so a certificate with a maximum validity of 45 days will be renewed every 30 days.
         * 
         * @return builder
         * 
         */
        public Builder maximumValidity(Integer maximumValidity) {
            return maximumValidity(Output.of(maximumValidity));
        }

        /**
         * @param mode (Updatable) DISABLED: Connection is not tunneled. PERMISSIVE: Connection can be either plaintext or an mTLS tunnel. STRICT: Connection is an mTLS tunnel.  Clients without a valid certificate will be rejected.
         * 
         * @return builder
         * 
         */
        public Builder mode(Output<String> mode) {
            $.mode = mode;
            return this;
        }

        /**
         * @param mode (Updatable) DISABLED: Connection is not tunneled. PERMISSIVE: Connection can be either plaintext or an mTLS tunnel. STRICT: Connection is an mTLS tunnel.  Clients without a valid certificate will be rejected.
         * 
         * @return builder
         * 
         */
        public Builder mode(String mode) {
            return mode(Output.of(mode));
        }

        public VirtualServiceMtlsArgs build() {
            if ($.mode == null) {
                throw new MissingRequiredPropertyException("VirtualServiceMtlsArgs", "mode");
            }
            return $;
        }
    }

}
