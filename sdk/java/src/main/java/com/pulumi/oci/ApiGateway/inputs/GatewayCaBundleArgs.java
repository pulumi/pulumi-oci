// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GatewayCaBundleArgs extends com.pulumi.resources.ResourceArgs {

    public static final GatewayCaBundleArgs Empty = new GatewayCaBundleArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    @Import(name="caBundleId")
    private @Nullable Output<String> caBundleId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    public Optional<Output<String>> caBundleId() {
        return Optional.ofNullable(this.caBundleId);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    @Import(name="certificateAuthorityId")
    private @Nullable Output<String> certificateAuthorityId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    public Optional<Output<String>> certificateAuthorityId() {
        return Optional.ofNullable(this.certificateAuthorityId);
    }

    /**
     * (Updatable) Type of the CA bundle
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) Type of the CA bundle
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    private GatewayCaBundleArgs() {}

    private GatewayCaBundleArgs(GatewayCaBundleArgs $) {
        this.caBundleId = $.caBundleId;
        this.certificateAuthorityId = $.certificateAuthorityId;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GatewayCaBundleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GatewayCaBundleArgs $;

        public Builder() {
            $ = new GatewayCaBundleArgs();
        }

        public Builder(GatewayCaBundleArgs defaults) {
            $ = new GatewayCaBundleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param caBundleId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
         * 
         * @return builder
         * 
         */
        public Builder caBundleId(@Nullable Output<String> caBundleId) {
            $.caBundleId = caBundleId;
            return this;
        }

        /**
         * @param caBundleId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
         * 
         * @return builder
         * 
         */
        public Builder caBundleId(String caBundleId) {
            return caBundleId(Output.of(caBundleId));
        }

        /**
         * @param certificateAuthorityId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
         * 
         * @return builder
         * 
         */
        public Builder certificateAuthorityId(@Nullable Output<String> certificateAuthorityId) {
            $.certificateAuthorityId = certificateAuthorityId;
            return this;
        }

        /**
         * @param certificateAuthorityId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
         * 
         * @return builder
         * 
         */
        public Builder certificateAuthorityId(String certificateAuthorityId) {
            return certificateAuthorityId(Output.of(certificateAuthorityId));
        }

        /**
         * @param type (Updatable) Type of the CA bundle
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) Type of the CA bundle
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public GatewayCaBundleArgs build() {
            if ($.type == null) {
                throw new MissingRequiredPropertyException("GatewayCaBundleArgs", "type");
            }
            return $;
        }
    }

}
