// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ocvp.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SddcVsphereUpgradeObjectArgs extends com.pulumi.resources.ResourceArgs {

    public static final SddcVsphereUpgradeObjectArgs Empty = new SddcVsphereUpgradeObjectArgs();

    /**
     * Binary object download link.
     * 
     */
    @Import(name="downloadLink")
    private @Nullable Output<String> downloadLink;

    /**
     * @return Binary object download link.
     * 
     */
    public Optional<Output<String>> downloadLink() {
        return Optional.ofNullable(this.downloadLink);
    }

    /**
     * Binary object description.
     * 
     */
    @Import(name="linkDescription")
    private @Nullable Output<String> linkDescription;

    /**
     * @return Binary object description.
     * 
     */
    public Optional<Output<String>> linkDescription() {
        return Optional.ofNullable(this.linkDescription);
    }

    private SddcVsphereUpgradeObjectArgs() {}

    private SddcVsphereUpgradeObjectArgs(SddcVsphereUpgradeObjectArgs $) {
        this.downloadLink = $.downloadLink;
        this.linkDescription = $.linkDescription;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SddcVsphereUpgradeObjectArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SddcVsphereUpgradeObjectArgs $;

        public Builder() {
            $ = new SddcVsphereUpgradeObjectArgs();
        }

        public Builder(SddcVsphereUpgradeObjectArgs defaults) {
            $ = new SddcVsphereUpgradeObjectArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param downloadLink Binary object download link.
         * 
         * @return builder
         * 
         */
        public Builder downloadLink(@Nullable Output<String> downloadLink) {
            $.downloadLink = downloadLink;
            return this;
        }

        /**
         * @param downloadLink Binary object download link.
         * 
         * @return builder
         * 
         */
        public Builder downloadLink(String downloadLink) {
            return downloadLink(Output.of(downloadLink));
        }

        /**
         * @param linkDescription Binary object description.
         * 
         * @return builder
         * 
         */
        public Builder linkDescription(@Nullable Output<String> linkDescription) {
            $.linkDescription = linkDescription;
            return this;
        }

        /**
         * @param linkDescription Binary object description.
         * 
         * @return builder
         * 
         */
        public Builder linkDescription(String linkDescription) {
            return linkDescription(Output.of(linkDescription));
        }

        public SddcVsphereUpgradeObjectArgs build() {
            return $;
        }
    }

}