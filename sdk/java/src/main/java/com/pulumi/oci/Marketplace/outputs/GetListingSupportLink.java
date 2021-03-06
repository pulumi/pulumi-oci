// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetListingSupportLink {
    /**
     * @return Text that describes the resource.
     * 
     */
    private final String name;
    /**
     * @return The URL of the resource.
     * 
     */
    private final String url;

    @CustomType.Constructor
    private GetListingSupportLink(
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("url") String url) {
        this.name = name;
        this.url = url;
    }

    /**
     * @return Text that describes the resource.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The URL of the resource.
     * 
     */
    public String url() {
        return this.url;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetListingSupportLink defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String name;
        private String url;

        public Builder() {
    	      // Empty
        }

        public Builder(GetListingSupportLink defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.url = defaults.url;
        }

        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder url(String url) {
            this.url = Objects.requireNonNull(url);
            return this;
        }        public GetListingSupportLink build() {
            return new GetListingSupportLink(name, url);
        }
    }
}
