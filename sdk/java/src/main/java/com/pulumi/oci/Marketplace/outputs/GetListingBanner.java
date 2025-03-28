// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetListingBanner {
    /**
     * @return The content URL of the screenshot.
     * 
     */
    private String contentUrl;
    /**
     * @return The file extension of the screenshot.
     * 
     */
    private String fileExtension;
    /**
     * @return The MIME type of the screenshot.
     * 
     */
    private String mimeType;
    /**
     * @return Text that describes the resource.
     * 
     */
    private String name;

    private GetListingBanner() {}
    /**
     * @return The content URL of the screenshot.
     * 
     */
    public String contentUrl() {
        return this.contentUrl;
    }
    /**
     * @return The file extension of the screenshot.
     * 
     */
    public String fileExtension() {
        return this.fileExtension;
    }
    /**
     * @return The MIME type of the screenshot.
     * 
     */
    public String mimeType() {
        return this.mimeType;
    }
    /**
     * @return Text that describes the resource.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetListingBanner defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String contentUrl;
        private String fileExtension;
        private String mimeType;
        private String name;
        public Builder() {}
        public Builder(GetListingBanner defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.contentUrl = defaults.contentUrl;
    	      this.fileExtension = defaults.fileExtension;
    	      this.mimeType = defaults.mimeType;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder contentUrl(String contentUrl) {
            if (contentUrl == null) {
              throw new MissingRequiredPropertyException("GetListingBanner", "contentUrl");
            }
            this.contentUrl = contentUrl;
            return this;
        }
        @CustomType.Setter
        public Builder fileExtension(String fileExtension) {
            if (fileExtension == null) {
              throw new MissingRequiredPropertyException("GetListingBanner", "fileExtension");
            }
            this.fileExtension = fileExtension;
            return this;
        }
        @CustomType.Setter
        public Builder mimeType(String mimeType) {
            if (mimeType == null) {
              throw new MissingRequiredPropertyException("GetListingBanner", "mimeType");
            }
            this.mimeType = mimeType;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetListingBanner", "name");
            }
            this.name = name;
            return this;
        }
        public GetListingBanner build() {
            final var _resultValue = new GetListingBanner();
            _resultValue.contentUrl = contentUrl;
            _resultValue.fileExtension = fileExtension;
            _resultValue.mimeType = mimeType;
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
