// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceCatalog.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PrivateApplicationLogoArgs extends com.pulumi.resources.ResourceArgs {

    public static final PrivateApplicationLogoArgs Empty = new PrivateApplicationLogoArgs();

    /**
     * The content URL of the uploaded data.
     * 
     */
    @Import(name="contentUrl")
    private @Nullable Output<String> contentUrl;

    /**
     * @return The content URL of the uploaded data.
     * 
     */
    public Optional<Output<String>> contentUrl() {
        return Optional.ofNullable(this.contentUrl);
    }

    /**
     * (Updatable) The name of the private application.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The name of the private application.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The MIME type of the uploaded data.
     * 
     */
    @Import(name="mimeType")
    private @Nullable Output<String> mimeType;

    /**
     * @return The MIME type of the uploaded data.
     * 
     */
    public Optional<Output<String>> mimeType() {
        return Optional.ofNullable(this.mimeType);
    }

    private PrivateApplicationLogoArgs() {}

    private PrivateApplicationLogoArgs(PrivateApplicationLogoArgs $) {
        this.contentUrl = $.contentUrl;
        this.displayName = $.displayName;
        this.mimeType = $.mimeType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PrivateApplicationLogoArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PrivateApplicationLogoArgs $;

        public Builder() {
            $ = new PrivateApplicationLogoArgs();
        }

        public Builder(PrivateApplicationLogoArgs defaults) {
            $ = new PrivateApplicationLogoArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param contentUrl The content URL of the uploaded data.
         * 
         * @return builder
         * 
         */
        public Builder contentUrl(@Nullable Output<String> contentUrl) {
            $.contentUrl = contentUrl;
            return this;
        }

        /**
         * @param contentUrl The content URL of the uploaded data.
         * 
         * @return builder
         * 
         */
        public Builder contentUrl(String contentUrl) {
            return contentUrl(Output.of(contentUrl));
        }

        /**
         * @param displayName (Updatable) The name of the private application.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The name of the private application.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param mimeType The MIME type of the uploaded data.
         * 
         * @return builder
         * 
         */
        public Builder mimeType(@Nullable Output<String> mimeType) {
            $.mimeType = mimeType;
            return this;
        }

        /**
         * @param mimeType The MIME type of the uploaded data.
         * 
         * @return builder
         * 
         */
        public Builder mimeType(String mimeType) {
            return mimeType(Output.of(mimeType));
        }

        public PrivateApplicationLogoArgs build() {
            return $;
        }
    }

}