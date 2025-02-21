// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.inputs.GetSqlCollectionLogInsightsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSqlCollectionLogInsightsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSqlCollectionLogInsightsArgs Empty = new GetSqlCollectionLogInsightsArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetSqlCollectionLogInsightsFilterArgs>> filters;

    public Optional<Output<List<GetSqlCollectionLogInsightsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The group by parameter to summarize SQL collection log insights aggregation.
     * 
     */
    @Import(name="groupBy")
    private @Nullable Output<String> groupBy;

    /**
     * @return The group by parameter to summarize SQL collection log insights aggregation.
     * 
     */
    public Optional<Output<String>> groupBy() {
        return Optional.ofNullable(this.groupBy);
    }

    /**
     * The OCID of the SQL collection resource.
     * 
     */
    @Import(name="sqlCollectionId", required=true)
    private Output<String> sqlCollectionId;

    /**
     * @return The OCID of the SQL collection resource.
     * 
     */
    public Output<String> sqlCollectionId() {
        return this.sqlCollectionId;
    }

    /**
     * An optional filter to return the stats of the SQL collection logs collected before the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Import(name="timeEnded", required=true)
    private Output<String> timeEnded;

    /**
     * @return An optional filter to return the stats of the SQL collection logs collected before the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Output<String> timeEnded() {
        return this.timeEnded;
    }

    /**
     * An optional filter to return the stats of the SQL collection logs collected after the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Import(name="timeStarted", required=true)
    private Output<String> timeStarted;

    /**
     * @return An optional filter to return the stats of the SQL collection logs collected after the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Output<String> timeStarted() {
        return this.timeStarted;
    }

    private GetSqlCollectionLogInsightsArgs() {}

    private GetSqlCollectionLogInsightsArgs(GetSqlCollectionLogInsightsArgs $) {
        this.filters = $.filters;
        this.groupBy = $.groupBy;
        this.sqlCollectionId = $.sqlCollectionId;
        this.timeEnded = $.timeEnded;
        this.timeStarted = $.timeStarted;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSqlCollectionLogInsightsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSqlCollectionLogInsightsArgs $;

        public Builder() {
            $ = new GetSqlCollectionLogInsightsArgs();
        }

        public Builder(GetSqlCollectionLogInsightsArgs defaults) {
            $ = new GetSqlCollectionLogInsightsArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetSqlCollectionLogInsightsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetSqlCollectionLogInsightsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetSqlCollectionLogInsightsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param groupBy The group by parameter to summarize SQL collection log insights aggregation.
         * 
         * @return builder
         * 
         */
        public Builder groupBy(@Nullable Output<String> groupBy) {
            $.groupBy = groupBy;
            return this;
        }

        /**
         * @param groupBy The group by parameter to summarize SQL collection log insights aggregation.
         * 
         * @return builder
         * 
         */
        public Builder groupBy(String groupBy) {
            return groupBy(Output.of(groupBy));
        }

        /**
         * @param sqlCollectionId The OCID of the SQL collection resource.
         * 
         * @return builder
         * 
         */
        public Builder sqlCollectionId(Output<String> sqlCollectionId) {
            $.sqlCollectionId = sqlCollectionId;
            return this;
        }

        /**
         * @param sqlCollectionId The OCID of the SQL collection resource.
         * 
         * @return builder
         * 
         */
        public Builder sqlCollectionId(String sqlCollectionId) {
            return sqlCollectionId(Output.of(sqlCollectionId));
        }

        /**
         * @param timeEnded An optional filter to return the stats of the SQL collection logs collected before the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeEnded(Output<String> timeEnded) {
            $.timeEnded = timeEnded;
            return this;
        }

        /**
         * @param timeEnded An optional filter to return the stats of the SQL collection logs collected before the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeEnded(String timeEnded) {
            return timeEnded(Output.of(timeEnded));
        }

        /**
         * @param timeStarted An optional filter to return the stats of the SQL collection logs collected after the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeStarted(Output<String> timeStarted) {
            $.timeStarted = timeStarted;
            return this;
        }

        /**
         * @param timeStarted An optional filter to return the stats of the SQL collection logs collected after the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeStarted(String timeStarted) {
            return timeStarted(Output.of(timeStarted));
        }

        public GetSqlCollectionLogInsightsArgs build() {
            if ($.sqlCollectionId == null) {
                throw new MissingRequiredPropertyException("GetSqlCollectionLogInsightsArgs", "sqlCollectionId");
            }
            if ($.timeEnded == null) {
                throw new MissingRequiredPropertyException("GetSqlCollectionLogInsightsArgs", "timeEnded");
            }
            if ($.timeStarted == null) {
                throw new MissingRequiredPropertyException("GetSqlCollectionLogInsightsArgs", "timeStarted");
            }
            return $;
        }
    }

}
