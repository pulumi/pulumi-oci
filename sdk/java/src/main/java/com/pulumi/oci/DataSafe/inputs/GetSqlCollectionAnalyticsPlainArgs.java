// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataSafe.inputs.GetSqlCollectionAnalyticsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSqlCollectionAnalyticsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSqlCollectionAnalyticsPlainArgs Empty = new GetSqlCollectionAnalyticsPlainArgs();

    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     * 
     */
    @Import(name="accessLevel")
    private @Nullable String accessLevel;

    /**
     * @return Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     * 
     */
    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }

    /**
     * A filter to return only resources that match the specified compartment OCID.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return A filter to return only resources that match the specified compartment OCID.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
     * 
     */
    @Import(name="compartmentIdInSubtree")
    private @Nullable Boolean compartmentIdInSubtree;

    /**
     * @return Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
     * 
     */
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }

    @Import(name="filters")
    private @Nullable List<GetSqlCollectionAnalyticsFilter> filters;

    public Optional<List<GetSqlCollectionAnalyticsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The group by parameter to summarize SQL collection aggregation.
     * 
     */
    @Import(name="groupBies")
    private @Nullable List<String> groupBies;

    /**
     * @return The group by parameter to summarize SQL collection aggregation.
     * 
     */
    public Optional<List<String>> groupBies() {
        return Optional.ofNullable(this.groupBies);
    }

    /**
     * The current state of the SQL collection.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The current state of the SQL collection.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only items related to a specific target OCID.
     * 
     */
    @Import(name="targetId")
    private @Nullable String targetId;

    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    public Optional<String> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    /**
     * An optional filter to return the stats of the SQL collection logs collected before the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Import(name="timeEnded")
    private @Nullable String timeEnded;

    /**
     * @return An optional filter to return the stats of the SQL collection logs collected before the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Optional<String> timeEnded() {
        return Optional.ofNullable(this.timeEnded);
    }

    /**
     * An optional filter to return the stats of the SQL collection logs collected after the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Import(name="timeStarted")
    private @Nullable String timeStarted;

    /**
     * @return An optional filter to return the stats of the SQL collection logs collected after the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Optional<String> timeStarted() {
        return Optional.ofNullable(this.timeStarted);
    }

    private GetSqlCollectionAnalyticsPlainArgs() {}

    private GetSqlCollectionAnalyticsPlainArgs(GetSqlCollectionAnalyticsPlainArgs $) {
        this.accessLevel = $.accessLevel;
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.filters = $.filters;
        this.groupBies = $.groupBies;
        this.state = $.state;
        this.targetId = $.targetId;
        this.timeEnded = $.timeEnded;
        this.timeStarted = $.timeStarted;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSqlCollectionAnalyticsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSqlCollectionAnalyticsPlainArgs $;

        public Builder() {
            $ = new GetSqlCollectionAnalyticsPlainArgs();
        }

        public Builder(GetSqlCollectionAnalyticsPlainArgs defaults) {
            $ = new GetSqlCollectionAnalyticsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param accessLevel Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
         * 
         * @return builder
         * 
         */
        public Builder accessLevel(@Nullable String accessLevel) {
            $.accessLevel = accessLevel;
            return this;
        }

        /**
         * @param compartmentId A filter to return only resources that match the specified compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentIdInSubtree Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {
            $.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }

        public Builder filters(@Nullable List<GetSqlCollectionAnalyticsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetSqlCollectionAnalyticsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param groupBies The group by parameter to summarize SQL collection aggregation.
         * 
         * @return builder
         * 
         */
        public Builder groupBies(@Nullable List<String> groupBies) {
            $.groupBies = groupBies;
            return this;
        }

        /**
         * @param groupBies The group by parameter to summarize SQL collection aggregation.
         * 
         * @return builder
         * 
         */
        public Builder groupBies(String... groupBies) {
            return groupBies(List.of(groupBies));
        }

        /**
         * @param state The current state of the SQL collection.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param targetId A filter to return only items related to a specific target OCID.
         * 
         * @return builder
         * 
         */
        public Builder targetId(@Nullable String targetId) {
            $.targetId = targetId;
            return this;
        }

        /**
         * @param timeEnded An optional filter to return the stats of the SQL collection logs collected before the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeEnded(@Nullable String timeEnded) {
            $.timeEnded = timeEnded;
            return this;
        }

        /**
         * @param timeStarted An optional filter to return the stats of the SQL collection logs collected after the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeStarted(@Nullable String timeStarted) {
            $.timeStarted = timeStarted;
            return this;
        }

        public GetSqlCollectionAnalyticsPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}