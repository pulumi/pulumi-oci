// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAwrHubAwrSnapshotPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAwrHubAwrSnapshotPlainArgs Empty = new GetAwrHubAwrSnapshotPlainArgs();

    /**
     * Unique Awr Hub identifier
     * 
     */
    @Import(name="awrHubId", required=true)
    private String awrHubId;

    /**
     * @return Unique Awr Hub identifier
     * 
     */
    public String awrHubId() {
        return this.awrHubId;
    }

    /**
     * AWR source database identifier.
     * 
     */
    @Import(name="awrSourceDatabaseIdentifier", required=true)
    private String awrSourceDatabaseIdentifier;

    /**
     * @return AWR source database identifier.
     * 
     */
    public String awrSourceDatabaseIdentifier() {
        return this.awrSourceDatabaseIdentifier;
    }

    /**
     * The optional greater than or equal to query parameter to filter the timestamp. The timestamp format to be followed is: YYYY-MM-DDTHH:MM:SSZ, example 2020-12-03T19:00:53Z
     * 
     */
    @Import(name="timeGreaterThanOrEqualTo")
    private @Nullable String timeGreaterThanOrEqualTo;

    /**
     * @return The optional greater than or equal to query parameter to filter the timestamp. The timestamp format to be followed is: YYYY-MM-DDTHH:MM:SSZ, example 2020-12-03T19:00:53Z
     * 
     */
    public Optional<String> timeGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeGreaterThanOrEqualTo);
    }

    /**
     * The optional less than or equal to query parameter to filter the timestamp. The timestamp format to be followed is: YYYY-MM-DDTHH:MM:SSZ, example 2020-12-03T19:00:53Z
     * 
     */
    @Import(name="timeLessThanOrEqualTo")
    private @Nullable String timeLessThanOrEqualTo;

    /**
     * @return The optional less than or equal to query parameter to filter the timestamp. The timestamp format to be followed is: YYYY-MM-DDTHH:MM:SSZ, example 2020-12-03T19:00:53Z
     * 
     */
    public Optional<String> timeLessThanOrEqualTo() {
        return Optional.ofNullable(this.timeLessThanOrEqualTo);
    }

    private GetAwrHubAwrSnapshotPlainArgs() {}

    private GetAwrHubAwrSnapshotPlainArgs(GetAwrHubAwrSnapshotPlainArgs $) {
        this.awrHubId = $.awrHubId;
        this.awrSourceDatabaseIdentifier = $.awrSourceDatabaseIdentifier;
        this.timeGreaterThanOrEqualTo = $.timeGreaterThanOrEqualTo;
        this.timeLessThanOrEqualTo = $.timeLessThanOrEqualTo;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAwrHubAwrSnapshotPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAwrHubAwrSnapshotPlainArgs $;

        public Builder() {
            $ = new GetAwrHubAwrSnapshotPlainArgs();
        }

        public Builder(GetAwrHubAwrSnapshotPlainArgs defaults) {
            $ = new GetAwrHubAwrSnapshotPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param awrHubId Unique Awr Hub identifier
         * 
         * @return builder
         * 
         */
        public Builder awrHubId(String awrHubId) {
            $.awrHubId = awrHubId;
            return this;
        }

        /**
         * @param awrSourceDatabaseIdentifier AWR source database identifier.
         * 
         * @return builder
         * 
         */
        public Builder awrSourceDatabaseIdentifier(String awrSourceDatabaseIdentifier) {
            $.awrSourceDatabaseIdentifier = awrSourceDatabaseIdentifier;
            return this;
        }

        /**
         * @param timeGreaterThanOrEqualTo The optional greater than or equal to query parameter to filter the timestamp. The timestamp format to be followed is: YYYY-MM-DDTHH:MM:SSZ, example 2020-12-03T19:00:53Z
         * 
         * @return builder
         * 
         */
        public Builder timeGreaterThanOrEqualTo(@Nullable String timeGreaterThanOrEqualTo) {
            $.timeGreaterThanOrEqualTo = timeGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeLessThanOrEqualTo The optional less than or equal to query parameter to filter the timestamp. The timestamp format to be followed is: YYYY-MM-DDTHH:MM:SSZ, example 2020-12-03T19:00:53Z
         * 
         * @return builder
         * 
         */
        public Builder timeLessThanOrEqualTo(@Nullable String timeLessThanOrEqualTo) {
            $.timeLessThanOrEqualTo = timeLessThanOrEqualTo;
            return this;
        }

        public GetAwrHubAwrSnapshotPlainArgs build() {
            if ($.awrHubId == null) {
                throw new MissingRequiredPropertyException("GetAwrHubAwrSnapshotPlainArgs", "awrHubId");
            }
            if ($.awrSourceDatabaseIdentifier == null) {
                throw new MissingRequiredPropertyException("GetAwrHubAwrSnapshotPlainArgs", "awrSourceDatabaseIdentifier");
            }
            return $;
        }
    }

}
