// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetTagStandardTagNamespaceTemplatesStandardTagNamespaceTemplate {
    /**
     * @return The default description of the tag namespace that users can use to create the tag namespace
     * 
     */
    private String description;
    /**
     * @return The reserved name of this standard tag namespace
     * 
     */
    private String standardTagNamespaceName;
    /**
     * @return The status of the standard tag namespace
     * 
     */
    private String status;

    private GetTagStandardTagNamespaceTemplatesStandardTagNamespaceTemplate() {}
    /**
     * @return The default description of the tag namespace that users can use to create the tag namespace
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The reserved name of this standard tag namespace
     * 
     */
    public String standardTagNamespaceName() {
        return this.standardTagNamespaceName;
    }
    /**
     * @return The status of the standard tag namespace
     * 
     */
    public String status() {
        return this.status;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTagStandardTagNamespaceTemplatesStandardTagNamespaceTemplate defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String description;
        private String standardTagNamespaceName;
        private String status;
        public Builder() {}
        public Builder(GetTagStandardTagNamespaceTemplatesStandardTagNamespaceTemplate defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.standardTagNamespaceName = defaults.standardTagNamespaceName;
    	      this.status = defaults.status;
        }

        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder standardTagNamespaceName(String standardTagNamespaceName) {
            this.standardTagNamespaceName = Objects.requireNonNull(standardTagNamespaceName);
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        public GetTagStandardTagNamespaceTemplatesStandardTagNamespaceTemplate build() {
            final var o = new GetTagStandardTagNamespaceTemplatesStandardTagNamespaceTemplate();
            o.description = description;
            o.standardTagNamespaceName = standardTagNamespaceName;
            o.status = status;
            return o;
        }
    }
}