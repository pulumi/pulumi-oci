// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RecommendationArgs extends com.pulumi.resources.ResourceArgs {

    public static final RecommendationArgs Empty = new RecommendationArgs();

    /**
     * The unique OCID associated with the recommendation.
     * 
     */
    @Import(name="recommendationId", required=true)
    private Output<String> recommendationId;

    /**
     * @return The unique OCID associated with the recommendation.
     * 
     */
    public Output<String> recommendationId() {
        return this.recommendationId;
    }

    /**
     * (Updatable) The status of the recommendation.
     * 
     */
    @Import(name="status", required=true)
    private Output<String> status;

    /**
     * @return (Updatable) The status of the recommendation.
     * 
     */
    public Output<String> status() {
        return this.status;
    }

    /**
     * (Updatable) The date and time the current status will change. The format is defined by RFC3339.
     * 
     * For example, &#34;The current `postponed` status of the recommendation will end and change to `pending` on this date and time.&#34;
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="timeStatusEnd")
    private @Nullable Output<String> timeStatusEnd;

    /**
     * @return (Updatable) The date and time the current status will change. The format is defined by RFC3339.
     * 
     * For example, &#34;The current `postponed` status of the recommendation will end and change to `pending` on this date and time.&#34;
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> timeStatusEnd() {
        return Optional.ofNullable(this.timeStatusEnd);
    }

    private RecommendationArgs() {}

    private RecommendationArgs(RecommendationArgs $) {
        this.recommendationId = $.recommendationId;
        this.status = $.status;
        this.timeStatusEnd = $.timeStatusEnd;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RecommendationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RecommendationArgs $;

        public Builder() {
            $ = new RecommendationArgs();
        }

        public Builder(RecommendationArgs defaults) {
            $ = new RecommendationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param recommendationId The unique OCID associated with the recommendation.
         * 
         * @return builder
         * 
         */
        public Builder recommendationId(Output<String> recommendationId) {
            $.recommendationId = recommendationId;
            return this;
        }

        /**
         * @param recommendationId The unique OCID associated with the recommendation.
         * 
         * @return builder
         * 
         */
        public Builder recommendationId(String recommendationId) {
            return recommendationId(Output.of(recommendationId));
        }

        /**
         * @param status (Updatable) The status of the recommendation.
         * 
         * @return builder
         * 
         */
        public Builder status(Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status (Updatable) The status of the recommendation.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param timeStatusEnd (Updatable) The date and time the current status will change. The format is defined by RFC3339.
         * 
         * For example, &#34;The current `postponed` status of the recommendation will end and change to `pending` on this date and time.&#34;
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder timeStatusEnd(@Nullable Output<String> timeStatusEnd) {
            $.timeStatusEnd = timeStatusEnd;
            return this;
        }

        /**
         * @param timeStatusEnd (Updatable) The date and time the current status will change. The format is defined by RFC3339.
         * 
         * For example, &#34;The current `postponed` status of the recommendation will end and change to `pending` on this date and time.&#34;
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder timeStatusEnd(String timeStatusEnd) {
            return timeStatusEnd(Output.of(timeStatusEnd));
        }

        public RecommendationArgs build() {
            if ($.recommendationId == null) {
                throw new MissingRequiredPropertyException("RecommendationArgs", "recommendationId");
            }
            if ($.status == null) {
                throw new MissingRequiredPropertyException("RecommendationArgs", "status");
            }
            return $;
        }
    }

}
