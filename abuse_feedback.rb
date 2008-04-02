class AbuseFeedback < ActiveRecord::Base
  belongs_to :email

  validates_uniqueness_of :uidl

  def self.pop3_settings=(args)
    @pop3_settings = args
  end

  def self.pop3_settings
    @pop3_settings ||= {:address   => 'pop.gmail.com',
                        :port      => 110,
                        :user_name => 'your_account@gmail.com',
                        :password  => '******'}
  end

  # Connect to the POP3 server and, for each message, process
  def self.receive
    serv = pop3_settings[:address]
    port = pop3_settings[:port]
    user = pop3_settings[:user_name]
    pass = pop3_settings[:password]

    logger.info "AbuseFeedback.receive called, connecting to #{serv}:#{port} as #{user}"
    Net::POP3.foreach(serv, port, user, pass) do |mail| 
      if process(mail.uidl, mail.pop) #returns true
        mail.delete
      end
    end 
    logger.info "AbuseFeedback.receive finished, disconnecting from #{serv}:#{port} as #{user}"
  end

  # The parse_mbox method is used to parse an mbox file.
  def self.parse_mbox(mbox_filename)
    RMail::Mailbox.parse_mbox(IO.read(mbox_filename)) do |raw_message|
      uidl = "mbox_#{rand(2**32)}"
      process(uidl, raw_message)
    end  
  end

  # Process a message. If the UIDL is in the DB, delete the message, if not, parse it. If
  # it parses (and stores) OK, delete it.
  def self.process(uidl, raw_message)
    raise ArgumentError, "uidl cannot be blank" if uidl.blank?
    raise ArgumentError, "raw_message cannot be blank" if raw_message.blank?

    if uidl_exists? uidl
      # That message has been processed, it's ok to delete it.
      logger.info "AbuseFeedback.process - UIDL '#{uidl}' exists and will be deleted"
      true
    elsif parse(uidl, raw_message)
      logger.info "AbuseFeedback.process - UIDL '#{uidl}' parsed successfully, will be deleted"
      true
    else
      logger.warn "AbuseFeedback.process - UIDL '#{uidl}' did not exist and could not be parsed, leaving it"
      false
    end
  end

  # parse the message, return true if it's safe to delete
  def self.parse(uidl, raw_message)
    raise ArgumentError, "uidl cannot be blank" if uidl.blank?
    raise ArgumentError, "raw_message cannot be blank" if raw_message.blank?

    # header          | text         
    # feedback_report | text         
    # source_ip       | varchar(255) 
    # message         | mediumtext   
    # message_subject | varchar(255) 
    # message_from    | varchar(255) 
    # email_id        | int(11)      
    # uidl          
   
    # RMail doesn't like \r\n, so strip that off. 
    message = RMail::Parser.read(raw_message.gsub(/\r/, ""))
    parts = []
    message.each_part {|part| parts << part }
    unless message.multipart? && parts.size == 3 && parts[1].header['content-type'] == "message/feedback-report"
      logger.warn "AbuseFeedback.parse: Parts of ARF message invalid, UIDL '#{uidl}'"
      return false
    end

    description = parts.shift # whatever, don't care about this part
    report      = parts.shift.body
    original    = RMail::Parser.read(parts.shift.body)

    params = {}
    params[:header]          = message.header.to_s
    params[:feedback_report] = report.to_s
    params[:message]         = original.to_s

    params[:uidl]            = uidl
    params[:source_ip]       = deduce_source_ip_from(report.to_s)
    params[:message_subject] = original.header['subject']
    params[:message_from]    = original.header['from']
    params[:email_id]        = original.header['x-email-id']
    
    feedback = AbuseFeedback.new params
    if feedback.save
      logger.info "AbuseFeedback.parse: Created new feedback ##{feedback.id} for #{feedback.message_from}"
      return true
    else
      logger.warn "AbuseFeedback.parse: Error creating feedback for '#{feedback.message_from}', UIDL '#{uidl}'"
      return false
    end
  end
  
  def self.find_unhandled(options = {})
    find(:all, options.merge(:conditions => "handled_at IS NULL"))
  end

  def self.count_unhandled
    count(:all, :conditions => "handled_at IS NULL")
  end
  
  # AbuseFeedback.handle_unhandled calls AbuseFeedback#handle! on all unhandled complaints
  def self.handle_unhandled
    orig_cnt = count_unhandled
    logger.info "AbuseFeedback.handle_unhandled called with #{orig_cnt} complaints to work on"
    cnt = 0
    while feedbacks = find_unhandled(:limit => 100) do 
      break if feedbacks.blank?
      feedbacks.each do |feedback| 
        feedback.handle!
        cnt += 1
      end
    end
    logger.info "AbuseFeedback.handle_unhandled finished after handling #{cnt} complaints."
  end

  def handled?
    handled_at != nil  
  end

  def handle!
    #
    # This is where you do something. 
    #
    fast_update_attribute :handled_at, Time.now.utc 
    logger.info "AbuseFeedback#handle! [#{id}] handling completed."
  end

  def self.uidl_exists?(u)
    self.count(:conditions => ["uidl = ?", u]) > 0
  end

  # Given the report, find the source IP
  def self.deduce_source_ip_from(raw_report)
    report = {} 
    raw_report.each_line do |line|
      field, value = line.split
      report[field] = value
    end
    report['Source-IP:']
  end
end
