// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsUserGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsUserGroupArgs Empty = new DomainsUserGroupArgs();

    /**
     * (Updatable) Date when the member is Added to the group
     * 
     */
    @Import(name="dateAdded")
    private @Nullable Output<String> dateAdded;

    /**
     * @return (Updatable) Date when the member is Added to the group
     * 
     */
    public Optional<Output<String>> dateAdded() {
        return Optional.ofNullable(this.dateAdded);
    }

    /**
     * (Updatable) A human readable name, primarily used for display purposes.
     * 
     */
    @Import(name="display")
    private @Nullable Output<String> display;

    /**
     * @return (Updatable) A human readable name, primarily used for display purposes.
     * 
     */
    public Optional<Output<String>> display() {
        return Optional.ofNullable(this.display);
    }

    /**
     * (Updatable) An identifier for the Resource as defined by the Service Consumer. READ-ONLY.
     * 
     */
    @Import(name="externalId")
    private @Nullable Output<String> externalId;

    /**
     * @return (Updatable) An identifier for the Resource as defined by the Service Consumer. READ-ONLY.
     * 
     */
    public Optional<Output<String>> externalId() {
        return Optional.ofNullable(this.externalId);
    }

    /**
     * (Updatable) Membership Ocid
     * 
     */
    @Import(name="membershipOcid")
    private @Nullable Output<String> membershipOcid;

    /**
     * @return (Updatable) Membership Ocid
     * 
     */
    public Optional<Output<String>> membershipOcid() {
        return Optional.ofNullable(this.membershipOcid);
    }

    /**
     * (Updatable) A human readable name for Group as defined by the Service Consumer. READ-ONLY.
     * 
     */
    @Import(name="nonUniqueDisplay")
    private @Nullable Output<String> nonUniqueDisplay;

    /**
     * @return (Updatable) A human readable name for Group as defined by the Service Consumer. READ-ONLY.
     * 
     */
    public Optional<Output<String>> nonUniqueDisplay() {
        return Optional.ofNullable(this.nonUniqueDisplay);
    }

    /**
     * (Updatable) Ocid of the User&#39;s Support Account.
     * 
     */
    @Import(name="ocid")
    private @Nullable Output<String> ocid;

    /**
     * @return (Updatable) Ocid of the User&#39;s Support Account.
     * 
     */
    public Optional<Output<String>> ocid() {
        return Optional.ofNullable(this.ocid);
    }

    /**
     * (Updatable) User Token URI
     * 
     */
    @Import(name="ref")
    private @Nullable Output<String> ref;

    /**
     * @return (Updatable) User Token URI
     * 
     */
    public Optional<Output<String>> ref() {
        return Optional.ofNullable(this.ref);
    }

    /**
     * (Updatable) A label indicating the attribute&#39;s function.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return (Updatable) A label indicating the attribute&#39;s function.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    /**
     * (Updatable) The value of a X509 certificate.
     * 
     */
    @Import(name="value", required=true)
    private Output<String> value;

    /**
     * @return (Updatable) The value of a X509 certificate.
     * 
     */
    public Output<String> value() {
        return this.value;
    }

    private DomainsUserGroupArgs() {}

    private DomainsUserGroupArgs(DomainsUserGroupArgs $) {
        this.dateAdded = $.dateAdded;
        this.display = $.display;
        this.externalId = $.externalId;
        this.membershipOcid = $.membershipOcid;
        this.nonUniqueDisplay = $.nonUniqueDisplay;
        this.ocid = $.ocid;
        this.ref = $.ref;
        this.type = $.type;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsUserGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsUserGroupArgs $;

        public Builder() {
            $ = new DomainsUserGroupArgs();
        }

        public Builder(DomainsUserGroupArgs defaults) {
            $ = new DomainsUserGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dateAdded (Updatable) Date when the member is Added to the group
         * 
         * @return builder
         * 
         */
        public Builder dateAdded(@Nullable Output<String> dateAdded) {
            $.dateAdded = dateAdded;
            return this;
        }

        /**
         * @param dateAdded (Updatable) Date when the member is Added to the group
         * 
         * @return builder
         * 
         */
        public Builder dateAdded(String dateAdded) {
            return dateAdded(Output.of(dateAdded));
        }

        /**
         * @param display (Updatable) A human readable name, primarily used for display purposes.
         * 
         * @return builder
         * 
         */
        public Builder display(@Nullable Output<String> display) {
            $.display = display;
            return this;
        }

        /**
         * @param display (Updatable) A human readable name, primarily used for display purposes.
         * 
         * @return builder
         * 
         */
        public Builder display(String display) {
            return display(Output.of(display));
        }

        /**
         * @param externalId (Updatable) An identifier for the Resource as defined by the Service Consumer. READ-ONLY.
         * 
         * @return builder
         * 
         */
        public Builder externalId(@Nullable Output<String> externalId) {
            $.externalId = externalId;
            return this;
        }

        /**
         * @param externalId (Updatable) An identifier for the Resource as defined by the Service Consumer. READ-ONLY.
         * 
         * @return builder
         * 
         */
        public Builder externalId(String externalId) {
            return externalId(Output.of(externalId));
        }

        /**
         * @param membershipOcid (Updatable) Membership Ocid
         * 
         * @return builder
         * 
         */
        public Builder membershipOcid(@Nullable Output<String> membershipOcid) {
            $.membershipOcid = membershipOcid;
            return this;
        }

        /**
         * @param membershipOcid (Updatable) Membership Ocid
         * 
         * @return builder
         * 
         */
        public Builder membershipOcid(String membershipOcid) {
            return membershipOcid(Output.of(membershipOcid));
        }

        /**
         * @param nonUniqueDisplay (Updatable) A human readable name for Group as defined by the Service Consumer. READ-ONLY.
         * 
         * @return builder
         * 
         */
        public Builder nonUniqueDisplay(@Nullable Output<String> nonUniqueDisplay) {
            $.nonUniqueDisplay = nonUniqueDisplay;
            return this;
        }

        /**
         * @param nonUniqueDisplay (Updatable) A human readable name for Group as defined by the Service Consumer. READ-ONLY.
         * 
         * @return builder
         * 
         */
        public Builder nonUniqueDisplay(String nonUniqueDisplay) {
            return nonUniqueDisplay(Output.of(nonUniqueDisplay));
        }

        /**
         * @param ocid (Updatable) Ocid of the User&#39;s Support Account.
         * 
         * @return builder
         * 
         */
        public Builder ocid(@Nullable Output<String> ocid) {
            $.ocid = ocid;
            return this;
        }

        /**
         * @param ocid (Updatable) Ocid of the User&#39;s Support Account.
         * 
         * @return builder
         * 
         */
        public Builder ocid(String ocid) {
            return ocid(Output.of(ocid));
        }

        /**
         * @param ref (Updatable) User Token URI
         * 
         * @return builder
         * 
         */
        public Builder ref(@Nullable Output<String> ref) {
            $.ref = ref;
            return this;
        }

        /**
         * @param ref (Updatable) User Token URI
         * 
         * @return builder
         * 
         */
        public Builder ref(String ref) {
            return ref(Output.of(ref));
        }

        /**
         * @param type (Updatable) A label indicating the attribute&#39;s function.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) A label indicating the attribute&#39;s function.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param value (Updatable) The value of a X509 certificate.
         * 
         * @return builder
         * 
         */
        public Builder value(Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) The value of a X509 certificate.
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public DomainsUserGroupArgs build() {
            $.value = Objects.requireNonNull($.value, "expected parameter 'value' to be non-null");
            return $;
        }
    }

}