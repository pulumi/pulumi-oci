// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataLabellingService.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAnnotationFormatItem {
    /**
     * @return A unique name for the target AnnotationFormat for the Dataset.
     * 
     */
    private String name;

    private GetAnnotationFormatItem() {}
    /**
     * @return A unique name for the target AnnotationFormat for the Dataset.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAnnotationFormatItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        public Builder() {}
        public Builder(GetAnnotationFormatItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public GetAnnotationFormatItem build() {
            final var o = new GetAnnotationFormatItem();
            o.name = name;
            return o;
        }
    }
}