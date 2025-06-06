// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PublicationIcon {
    /**
     * @return The content URL of the upload data.
     * 
     */
    private @Nullable String contentUrl;
    /**
     * @return The file extension of the upload data.
     * 
     */
    private @Nullable String fileExtension;
    /**
     * @return The MIME type of the upload data.
     * 
     */
    private @Nullable String mimeType;
    /**
     * @return (Updatable) The name of the publication, which is also used in the listing.
     * 
     */
    private @Nullable String name;

    private PublicationIcon() {}
    /**
     * @return The content URL of the upload data.
     * 
     */
    public Optional<String> contentUrl() {
        return Optional.ofNullable(this.contentUrl);
    }
    /**
     * @return The file extension of the upload data.
     * 
     */
    public Optional<String> fileExtension() {
        return Optional.ofNullable(this.fileExtension);
    }
    /**
     * @return The MIME type of the upload data.
     * 
     */
    public Optional<String> mimeType() {
        return Optional.ofNullable(this.mimeType);
    }
    /**
     * @return (Updatable) The name of the publication, which is also used in the listing.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PublicationIcon defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String contentUrl;
        private @Nullable String fileExtension;
        private @Nullable String mimeType;
        private @Nullable String name;
        public Builder() {}
        public Builder(PublicationIcon defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.contentUrl = defaults.contentUrl;
    	      this.fileExtension = defaults.fileExtension;
    	      this.mimeType = defaults.mimeType;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder contentUrl(@Nullable String contentUrl) {

            this.contentUrl = contentUrl;
            return this;
        }
        @CustomType.Setter
        public Builder fileExtension(@Nullable String fileExtension) {

            this.fileExtension = fileExtension;
            return this;
        }
        @CustomType.Setter
        public Builder mimeType(@Nullable String mimeType) {

            this.mimeType = mimeType;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        public PublicationIcon build() {
            final var _resultValue = new PublicationIcon();
            _resultValue.contentUrl = contentUrl;
            _resultValue.fileExtension = fileExtension;
            _resultValue.mimeType = mimeType;
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
