// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseAttentionLogCountsAttentionLogCountsCollectionItem {
    /**
     * @return The category of different attention logs.
     * 
     */
    private String category;
    /**
     * @return The count of attention logs with specific category.
     * 
     */
    private Integer count;

    private GetManagedDatabaseAttentionLogCountsAttentionLogCountsCollectionItem() {}
    /**
     * @return The category of different attention logs.
     * 
     */
    public String category() {
        return this.category;
    }
    /**
     * @return The count of attention logs with specific category.
     * 
     */
    public Integer count() {
        return this.count;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseAttentionLogCountsAttentionLogCountsCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String category;
        private Integer count;
        public Builder() {}
        public Builder(GetManagedDatabaseAttentionLogCountsAttentionLogCountsCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.category = defaults.category;
    	      this.count = defaults.count;
        }

        @CustomType.Setter
        public Builder category(String category) {
            if (category == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAttentionLogCountsAttentionLogCountsCollectionItem", "category");
            }
            this.category = category;
            return this;
        }
        @CustomType.Setter
        public Builder count(Integer count) {
            if (count == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAttentionLogCountsAttentionLogCountsCollectionItem", "count");
            }
            this.count = count;
            return this;
        }
        public GetManagedDatabaseAttentionLogCountsAttentionLogCountsCollectionItem build() {
            final var _resultValue = new GetManagedDatabaseAttentionLogCountsAttentionLogCountsCollectionItem();
            _resultValue.category = category;
            _resultValue.count = count;
            return _resultValue;
        }
    }
}
