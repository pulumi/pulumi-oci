// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetFusionEnvironmentTimeAvailableForRefreshsTimeAvailableForRefreshCollectionItem {
    /**
     * @return refresh time.
     * 
     */
    private String timeAvailableForRefresh;

    private GetFusionEnvironmentTimeAvailableForRefreshsTimeAvailableForRefreshCollectionItem() {}
    /**
     * @return refresh time.
     * 
     */
    public String timeAvailableForRefresh() {
        return this.timeAvailableForRefresh;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFusionEnvironmentTimeAvailableForRefreshsTimeAvailableForRefreshCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String timeAvailableForRefresh;
        public Builder() {}
        public Builder(GetFusionEnvironmentTimeAvailableForRefreshsTimeAvailableForRefreshCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.timeAvailableForRefresh = defaults.timeAvailableForRefresh;
        }

        @CustomType.Setter
        public Builder timeAvailableForRefresh(String timeAvailableForRefresh) {
            if (timeAvailableForRefresh == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentTimeAvailableForRefreshsTimeAvailableForRefreshCollectionItem", "timeAvailableForRefresh");
            }
            this.timeAvailableForRefresh = timeAvailableForRefresh;
            return this;
        }
        public GetFusionEnvironmentTimeAvailableForRefreshsTimeAvailableForRefreshCollectionItem build() {
            final var _resultValue = new GetFusionEnvironmentTimeAvailableForRefreshsTimeAvailableForRefreshCollectionItem();
            _resultValue.timeAvailableForRefresh = timeAvailableForRefresh;
            return _resultValue;
        }
    }
}
