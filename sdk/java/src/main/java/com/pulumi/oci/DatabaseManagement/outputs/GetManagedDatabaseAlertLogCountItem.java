// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseAlertLogCountItem {
    /**
     * @return The category of different alert logs.
     * 
     */
    private String category;
    /**
     * @return The count of alert logs with specific category.
     * 
     */
    private Integer count;

    private GetManagedDatabaseAlertLogCountItem() {}
    /**
     * @return The category of different alert logs.
     * 
     */
    public String category() {
        return this.category;
    }
    /**
     * @return The count of alert logs with specific category.
     * 
     */
    public Integer count() {
        return this.count;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseAlertLogCountItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String category;
        private Integer count;
        public Builder() {}
        public Builder(GetManagedDatabaseAlertLogCountItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.category = defaults.category;
    	      this.count = defaults.count;
        }

        @CustomType.Setter
        public Builder category(String category) {
            this.category = Objects.requireNonNull(category);
            return this;
        }
        @CustomType.Setter
        public Builder count(Integer count) {
            this.count = Objects.requireNonNull(count);
            return this;
        }
        public GetManagedDatabaseAlertLogCountItem build() {
            final var o = new GetManagedDatabaseAlertLogCountItem();
            o.category = category;
            o.count = count;
            return o;
        }
    }
}