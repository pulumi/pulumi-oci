// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PublicationPackageDetailsEulaArgs extends com.pulumi.resources.ResourceArgs {

    public static final PublicationPackageDetailsEulaArgs Empty = new PublicationPackageDetailsEulaArgs();

    /**
     * The end user license agreement&#39;s type.
     * 
     */
    @Import(name="eulaType", required=true)
    private Output<String> eulaType;

    /**
     * @return The end user license agreement&#39;s type.
     * 
     */
    public Output<String> eulaType() {
        return this.eulaType;
    }

    /**
     * The text of the end user license agreement.
     * 
     */
    @Import(name="licenseText")
    private @Nullable Output<String> licenseText;

    /**
     * @return The text of the end user license agreement.
     * 
     */
    public Optional<Output<String>> licenseText() {
        return Optional.ofNullable(this.licenseText);
    }

    private PublicationPackageDetailsEulaArgs() {}

    private PublicationPackageDetailsEulaArgs(PublicationPackageDetailsEulaArgs $) {
        this.eulaType = $.eulaType;
        this.licenseText = $.licenseText;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PublicationPackageDetailsEulaArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PublicationPackageDetailsEulaArgs $;

        public Builder() {
            $ = new PublicationPackageDetailsEulaArgs();
        }

        public Builder(PublicationPackageDetailsEulaArgs defaults) {
            $ = new PublicationPackageDetailsEulaArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param eulaType The end user license agreement&#39;s type.
         * 
         * @return builder
         * 
         */
        public Builder eulaType(Output<String> eulaType) {
            $.eulaType = eulaType;
            return this;
        }

        /**
         * @param eulaType The end user license agreement&#39;s type.
         * 
         * @return builder
         * 
         */
        public Builder eulaType(String eulaType) {
            return eulaType(Output.of(eulaType));
        }

        /**
         * @param licenseText The text of the end user license agreement.
         * 
         * @return builder
         * 
         */
        public Builder licenseText(@Nullable Output<String> licenseText) {
            $.licenseText = licenseText;
            return this;
        }

        /**
         * @param licenseText The text of the end user license agreement.
         * 
         * @return builder
         * 
         */
        public Builder licenseText(String licenseText) {
            return licenseText(Output.of(licenseText));
        }

        public PublicationPackageDetailsEulaArgs build() {
            $.eulaType = Objects.requireNonNull($.eulaType, "expected parameter 'eulaType' to be non-null");
            return $;
        }
    }

}