// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Jms.inputs.GetJavaReleasesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetJavaReleasesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetJavaReleasesPlainArgs Empty = new GetJavaReleasesPlainArgs();

    /**
     * The version identifier for the Java family.
     * 
     */
    @Import(name="familyVersion")
    private @Nullable String familyVersion;

    /**
     * @return The version identifier for the Java family.
     * 
     */
    public Optional<String> familyVersion() {
        return Optional.ofNullable(this.familyVersion);
    }

    @Import(name="filters")
    private @Nullable List<GetJavaReleasesFilter> filters;

    public Optional<List<GetJavaReleasesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The security status of the Java Runtime.
     * 
     */
    @Import(name="jreSecurityStatus")
    private @Nullable String jreSecurityStatus;

    /**
     * @return The security status of the Java Runtime.
     * 
     */
    public Optional<String> jreSecurityStatus() {
        return Optional.ofNullable(this.jreSecurityStatus);
    }

    /**
     * Java license type.
     * 
     */
    @Import(name="licenseType")
    private @Nullable String licenseType;

    /**
     * @return Java license type.
     * 
     */
    public Optional<String> licenseType() {
        return Optional.ofNullable(this.licenseType);
    }

    /**
     * Java release type.
     * 
     */
    @Import(name="releaseType")
    private @Nullable String releaseType;

    /**
     * @return Java release type.
     * 
     */
    public Optional<String> releaseType() {
        return Optional.ofNullable(this.releaseType);
    }

    /**
     * Unique Java release version identifier
     * 
     */
    @Import(name="releaseVersion")
    private @Nullable String releaseVersion;

    /**
     * @return Unique Java release version identifier
     * 
     */
    public Optional<String> releaseVersion() {
        return Optional.ofNullable(this.releaseVersion);
    }

    private GetJavaReleasesPlainArgs() {}

    private GetJavaReleasesPlainArgs(GetJavaReleasesPlainArgs $) {
        this.familyVersion = $.familyVersion;
        this.filters = $.filters;
        this.jreSecurityStatus = $.jreSecurityStatus;
        this.licenseType = $.licenseType;
        this.releaseType = $.releaseType;
        this.releaseVersion = $.releaseVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetJavaReleasesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetJavaReleasesPlainArgs $;

        public Builder() {
            $ = new GetJavaReleasesPlainArgs();
        }

        public Builder(GetJavaReleasesPlainArgs defaults) {
            $ = new GetJavaReleasesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param familyVersion The version identifier for the Java family.
         * 
         * @return builder
         * 
         */
        public Builder familyVersion(@Nullable String familyVersion) {
            $.familyVersion = familyVersion;
            return this;
        }

        public Builder filters(@Nullable List<GetJavaReleasesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetJavaReleasesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param jreSecurityStatus The security status of the Java Runtime.
         * 
         * @return builder
         * 
         */
        public Builder jreSecurityStatus(@Nullable String jreSecurityStatus) {
            $.jreSecurityStatus = jreSecurityStatus;
            return this;
        }

        /**
         * @param licenseType Java license type.
         * 
         * @return builder
         * 
         */
        public Builder licenseType(@Nullable String licenseType) {
            $.licenseType = licenseType;
            return this;
        }

        /**
         * @param releaseType Java release type.
         * 
         * @return builder
         * 
         */
        public Builder releaseType(@Nullable String releaseType) {
            $.releaseType = releaseType;
            return this;
        }

        /**
         * @param releaseVersion Unique Java release version identifier
         * 
         * @return builder
         * 
         */
        public Builder releaseVersion(@Nullable String releaseVersion) {
            $.releaseVersion = releaseVersion;
            return this;
        }

        public GetJavaReleasesPlainArgs build() {
            return $;
        }
    }

}