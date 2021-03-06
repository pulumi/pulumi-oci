// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRecommendationsRecommendationCollectionItemResourceCount {
    /**
     * @return The count of resources.
     * 
     */
    private final Integer count;
    /**
     * @return A filter that returns recommendations that match the status specified.
     * 
     */
    private final String status;

    @CustomType.Constructor
    private GetRecommendationsRecommendationCollectionItemResourceCount(
        @CustomType.Parameter("count") Integer count,
        @CustomType.Parameter("status") String status) {
        this.count = count;
        this.status = status;
    }

    /**
     * @return The count of resources.
     * 
     */
    public Integer count() {
        return this.count;
    }
    /**
     * @return A filter that returns recommendations that match the status specified.
     * 
     */
    public String status() {
        return this.status;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRecommendationsRecommendationCollectionItemResourceCount defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Integer count;
        private String status;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRecommendationsRecommendationCollectionItemResourceCount defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.count = defaults.count;
    	      this.status = defaults.status;
        }

        public Builder count(Integer count) {
            this.count = Objects.requireNonNull(count);
            return this;
        }
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }        public GetRecommendationsRecommendationCollectionItemResourceCount build() {
            return new GetRecommendationsRecommendationCollectionItemResourceCount(count, status);
        }
    }
}
