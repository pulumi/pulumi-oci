// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opensearch.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetOpensearchVersionsOpensearchVersionsCollectionItem {
    /**
     * @return The version of OpenSearch.
     * 
     */
    private String version;

    private GetOpensearchVersionsOpensearchVersionsCollectionItem() {}
    /**
     * @return The version of OpenSearch.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOpensearchVersionsOpensearchVersionsCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String version;
        public Builder() {}
        public Builder(GetOpensearchVersionsOpensearchVersionsCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetOpensearchVersionsOpensearchVersionsCollectionItem", "version");
            }
            this.version = version;
            return this;
        }
        public GetOpensearchVersionsOpensearchVersionsCollectionItem build() {
            final var _resultValue = new GetOpensearchVersionsOpensearchVersionsCollectionItem();
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
