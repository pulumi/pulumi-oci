// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRecommendationResourceCount {
    /**
     * @return The count of resources.
     * 
     */
    private Integer count;
    /**
     * @return The current status of the recommendation.
     * 
     */
    private String status;

    private GetRecommendationResourceCount() {}
    /**
     * @return The count of resources.
     * 
     */
    public Integer count() {
        return this.count;
    }
    /**
     * @return The current status of the recommendation.
     * 
     */
    public String status() {
        return this.status;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRecommendationResourceCount defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer count;
        private String status;
        public Builder() {}
        public Builder(GetRecommendationResourceCount defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.count = defaults.count;
    	      this.status = defaults.status;
        }

        @CustomType.Setter
        public Builder count(Integer count) {
            this.count = Objects.requireNonNull(count);
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        public GetRecommendationResourceCount build() {
            final var o = new GetRecommendationResourceCount();
            o.count = count;
            o.status = status;
            return o;
        }
    }
}