// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Jms.inputs.GetAnnouncementsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAnnouncementsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAnnouncementsPlainArgs Empty = new GetAnnouncementsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetAnnouncementsFilter> filters;

    public Optional<List<GetAnnouncementsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Filter the list with summary contains the given value.
     * 
     */
    @Import(name="summaryContains")
    private @Nullable String summaryContains;

    /**
     * @return Filter the list with summary contains the given value.
     * 
     */
    public Optional<String> summaryContains() {
        return Optional.ofNullable(this.summaryContains);
    }

    /**
     * The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    @Import(name="timeEnd")
    private @Nullable String timeEnd;

    /**
     * @return The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    public Optional<String> timeEnd() {
        return Optional.ofNullable(this.timeEnd);
    }

    /**
     * The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    @Import(name="timeStart")
    private @Nullable String timeStart;

    /**
     * @return The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    public Optional<String> timeStart() {
        return Optional.ofNullable(this.timeStart);
    }

    private GetAnnouncementsPlainArgs() {}

    private GetAnnouncementsPlainArgs(GetAnnouncementsPlainArgs $) {
        this.filters = $.filters;
        this.summaryContains = $.summaryContains;
        this.timeEnd = $.timeEnd;
        this.timeStart = $.timeStart;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAnnouncementsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAnnouncementsPlainArgs $;

        public Builder() {
            $ = new GetAnnouncementsPlainArgs();
        }

        public Builder(GetAnnouncementsPlainArgs defaults) {
            $ = new GetAnnouncementsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetAnnouncementsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetAnnouncementsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param summaryContains Filter the list with summary contains the given value.
         * 
         * @return builder
         * 
         */
        public Builder summaryContains(@Nullable String summaryContains) {
            $.summaryContains = summaryContains;
            return this;
        }

        /**
         * @param timeEnd The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
         * 
         * @return builder
         * 
         */
        public Builder timeEnd(@Nullable String timeEnd) {
            $.timeEnd = timeEnd;
            return this;
        }

        /**
         * @param timeStart The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
         * 
         * @return builder
         * 
         */
        public Builder timeStart(@Nullable String timeStart) {
            $.timeStart = timeStart;
            return this;
        }

        public GetAnnouncementsPlainArgs build() {
            return $;
        }
    }

}