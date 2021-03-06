// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetListingPackageAgreementsAgreement {
    /**
     * @return Who authored the agreement.
     * 
     */
    private final String author;
    /**
     * @return The content URL of the agreement.
     * 
     */
    private final String contentUrl;
    /**
     * @return The unique identifier for the agreement.
     * 
     */
    private final String id;
    /**
     * @return Textual prompt to read and accept the agreement.
     * 
     */
    private final String prompt;

    @CustomType.Constructor
    private GetListingPackageAgreementsAgreement(
        @CustomType.Parameter("author") String author,
        @CustomType.Parameter("contentUrl") String contentUrl,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("prompt") String prompt) {
        this.author = author;
        this.contentUrl = contentUrl;
        this.id = id;
        this.prompt = prompt;
    }

    /**
     * @return Who authored the agreement.
     * 
     */
    public String author() {
        return this.author;
    }
    /**
     * @return The content URL of the agreement.
     * 
     */
    public String contentUrl() {
        return this.contentUrl;
    }
    /**
     * @return The unique identifier for the agreement.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Textual prompt to read and accept the agreement.
     * 
     */
    public String prompt() {
        return this.prompt;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetListingPackageAgreementsAgreement defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String author;
        private String contentUrl;
        private String id;
        private String prompt;

        public Builder() {
    	      // Empty
        }

        public Builder(GetListingPackageAgreementsAgreement defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.author = defaults.author;
    	      this.contentUrl = defaults.contentUrl;
    	      this.id = defaults.id;
    	      this.prompt = defaults.prompt;
        }

        public Builder author(String author) {
            this.author = Objects.requireNonNull(author);
            return this;
        }
        public Builder contentUrl(String contentUrl) {
            this.contentUrl = Objects.requireNonNull(contentUrl);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder prompt(String prompt) {
            this.prompt = Objects.requireNonNull(prompt);
            return this;
        }        public GetListingPackageAgreementsAgreement build() {
            return new GetListingPackageAgreementsAgreement(author, contentUrl, id, prompt);
        }
    }
}
