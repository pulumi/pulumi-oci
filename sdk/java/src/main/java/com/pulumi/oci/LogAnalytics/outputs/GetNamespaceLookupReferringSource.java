// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetNamespaceLookupReferringSource {
    /**
     * @return The canonical link.
     * 
     */
    private String canonicalLink;
    /**
     * @return The total count.
     * 
     */
    private String totalCount;

    private GetNamespaceLookupReferringSource() {}
    /**
     * @return The canonical link.
     * 
     */
    public String canonicalLink() {
        return this.canonicalLink;
    }
    /**
     * @return The total count.
     * 
     */
    public String totalCount() {
        return this.totalCount;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceLookupReferringSource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String canonicalLink;
        private String totalCount;
        public Builder() {}
        public Builder(GetNamespaceLookupReferringSource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.canonicalLink = defaults.canonicalLink;
    	      this.totalCount = defaults.totalCount;
        }

        @CustomType.Setter
        public Builder canonicalLink(String canonicalLink) {
            if (canonicalLink == null) {
              throw new MissingRequiredPropertyException("GetNamespaceLookupReferringSource", "canonicalLink");
            }
            this.canonicalLink = canonicalLink;
            return this;
        }
        @CustomType.Setter
        public Builder totalCount(String totalCount) {
            if (totalCount == null) {
              throw new MissingRequiredPropertyException("GetNamespaceLookupReferringSource", "totalCount");
            }
            this.totalCount = totalCount;
            return this;
        }
        public GetNamespaceLookupReferringSource build() {
            final var _resultValue = new GetNamespaceLookupReferringSource();
            _resultValue.canonicalLink = canonicalLink;
            _resultValue.totalCount = totalCount;
            return _resultValue;
        }
    }
}
