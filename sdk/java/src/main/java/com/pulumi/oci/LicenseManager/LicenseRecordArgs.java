// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LicenseManager;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class LicenseRecordArgs extends com.pulumi.resources.ResourceArgs {

    public static final LicenseRecordArgs Empty = new LicenseRecordArgs();

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) License record name.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) License record name.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) The license record end date in [RFC 3339](https://tools.ietf.org/html/rfc3339) date format. Example: `2018-09-12`
     * 
     */
    @Import(name="expirationDate")
    private @Nullable Output<String> expirationDate;

    /**
     * @return (Updatable) The license record end date in [RFC 3339](https://tools.ietf.org/html/rfc3339) date format. Example: `2018-09-12`
     * 
     */
    public Optional<Output<String>> expirationDate() {
        return Optional.ofNullable(this.expirationDate);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Specifies if the license record term is perpertual.
     * 
     */
    @Import(name="isPerpetual", required=true)
    private Output<Boolean> isPerpetual;

    /**
     * @return (Updatable) Specifies if the license record term is perpertual.
     * 
     */
    public Output<Boolean> isPerpetual() {
        return this.isPerpetual;
    }

    /**
     * (Updatable) Specifies if the license count is unlimited.
     * 
     */
    @Import(name="isUnlimited", required=true)
    private Output<Boolean> isUnlimited;

    /**
     * @return (Updatable) Specifies if the license count is unlimited.
     * 
     */
    public Output<Boolean> isUnlimited() {
        return this.isUnlimited;
    }

    /**
     * (Updatable) The number of license units added by a user in a license record. Default 1
     * 
     */
    @Import(name="licenseCount")
    private @Nullable Output<Integer> licenseCount;

    /**
     * @return (Updatable) The number of license units added by a user in a license record. Default 1
     * 
     */
    public Optional<Output<Integer>> licenseCount() {
        return Optional.ofNullable(this.licenseCount);
    }

    /**
     * (Updatable) The license record product ID.
     * 
     */
    @Import(name="productId")
    private @Nullable Output<String> productId;

    /**
     * @return (Updatable) The license record product ID.
     * 
     */
    public Optional<Output<String>> productId() {
        return Optional.ofNullable(this.productId);
    }

    /**
     * Unique product license identifier.
     * 
     */
    @Import(name="productLicenseId", required=true)
    private Output<String> productLicenseId;

    /**
     * @return Unique product license identifier.
     * 
     */
    public Output<String> productLicenseId() {
        return this.productLicenseId;
    }

    /**
     * (Updatable) The license record support end date in [RFC 3339](https://tools.ietf.org/html/rfc3339) date format. Example: `2018-09-12`
     * 
     */
    @Import(name="supportEndDate")
    private @Nullable Output<String> supportEndDate;

    /**
     * @return (Updatable) The license record support end date in [RFC 3339](https://tools.ietf.org/html/rfc3339) date format. Example: `2018-09-12`
     * 
     */
    public Optional<Output<String>> supportEndDate() {
        return Optional.ofNullable(this.supportEndDate);
    }

    private LicenseRecordArgs() {}

    private LicenseRecordArgs(LicenseRecordArgs $) {
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.expirationDate = $.expirationDate;
        this.freeformTags = $.freeformTags;
        this.isPerpetual = $.isPerpetual;
        this.isUnlimited = $.isUnlimited;
        this.licenseCount = $.licenseCount;
        this.productId = $.productId;
        this.productLicenseId = $.productLicenseId;
        this.supportEndDate = $.supportEndDate;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(LicenseRecordArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private LicenseRecordArgs $;

        public Builder() {
            $ = new LicenseRecordArgs();
        }

        public Builder(LicenseRecordArgs defaults) {
            $ = new LicenseRecordArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) License record name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) License record name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param expirationDate (Updatable) The license record end date in [RFC 3339](https://tools.ietf.org/html/rfc3339) date format. Example: `2018-09-12`
         * 
         * @return builder
         * 
         */
        public Builder expirationDate(@Nullable Output<String> expirationDate) {
            $.expirationDate = expirationDate;
            return this;
        }

        /**
         * @param expirationDate (Updatable) The license record end date in [RFC 3339](https://tools.ietf.org/html/rfc3339) date format. Example: `2018-09-12`
         * 
         * @return builder
         * 
         */
        public Builder expirationDate(String expirationDate) {
            return expirationDate(Output.of(expirationDate));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isPerpetual (Updatable) Specifies if the license record term is perpertual.
         * 
         * @return builder
         * 
         */
        public Builder isPerpetual(Output<Boolean> isPerpetual) {
            $.isPerpetual = isPerpetual;
            return this;
        }

        /**
         * @param isPerpetual (Updatable) Specifies if the license record term is perpertual.
         * 
         * @return builder
         * 
         */
        public Builder isPerpetual(Boolean isPerpetual) {
            return isPerpetual(Output.of(isPerpetual));
        }

        /**
         * @param isUnlimited (Updatable) Specifies if the license count is unlimited.
         * 
         * @return builder
         * 
         */
        public Builder isUnlimited(Output<Boolean> isUnlimited) {
            $.isUnlimited = isUnlimited;
            return this;
        }

        /**
         * @param isUnlimited (Updatable) Specifies if the license count is unlimited.
         * 
         * @return builder
         * 
         */
        public Builder isUnlimited(Boolean isUnlimited) {
            return isUnlimited(Output.of(isUnlimited));
        }

        /**
         * @param licenseCount (Updatable) The number of license units added by a user in a license record. Default 1
         * 
         * @return builder
         * 
         */
        public Builder licenseCount(@Nullable Output<Integer> licenseCount) {
            $.licenseCount = licenseCount;
            return this;
        }

        /**
         * @param licenseCount (Updatable) The number of license units added by a user in a license record. Default 1
         * 
         * @return builder
         * 
         */
        public Builder licenseCount(Integer licenseCount) {
            return licenseCount(Output.of(licenseCount));
        }

        /**
         * @param productId (Updatable) The license record product ID.
         * 
         * @return builder
         * 
         */
        public Builder productId(@Nullable Output<String> productId) {
            $.productId = productId;
            return this;
        }

        /**
         * @param productId (Updatable) The license record product ID.
         * 
         * @return builder
         * 
         */
        public Builder productId(String productId) {
            return productId(Output.of(productId));
        }

        /**
         * @param productLicenseId Unique product license identifier.
         * 
         * @return builder
         * 
         */
        public Builder productLicenseId(Output<String> productLicenseId) {
            $.productLicenseId = productLicenseId;
            return this;
        }

        /**
         * @param productLicenseId Unique product license identifier.
         * 
         * @return builder
         * 
         */
        public Builder productLicenseId(String productLicenseId) {
            return productLicenseId(Output.of(productLicenseId));
        }

        /**
         * @param supportEndDate (Updatable) The license record support end date in [RFC 3339](https://tools.ietf.org/html/rfc3339) date format. Example: `2018-09-12`
         * 
         * @return builder
         * 
         */
        public Builder supportEndDate(@Nullable Output<String> supportEndDate) {
            $.supportEndDate = supportEndDate;
            return this;
        }

        /**
         * @param supportEndDate (Updatable) The license record support end date in [RFC 3339](https://tools.ietf.org/html/rfc3339) date format. Example: `2018-09-12`
         * 
         * @return builder
         * 
         */
        public Builder supportEndDate(String supportEndDate) {
            return supportEndDate(Output.of(supportEndDate));
        }

        public LicenseRecordArgs build() {
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.isPerpetual = Objects.requireNonNull($.isPerpetual, "expected parameter 'isPerpetual' to be non-null");
            $.isUnlimited = Objects.requireNonNull($.isUnlimited, "expected parameter 'isUnlimited' to be non-null");
            $.productLicenseId = Objects.requireNonNull($.productLicenseId, "expected parameter 'productLicenseId' to be non-null");
            return $;
        }
    }

}