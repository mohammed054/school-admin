require('dotenv').config();
const mongoose = require('mongoose');

const contentData = {
  home: {
    hero_title_1: 'مدرسة الحكمة الخاصة | تعليم متميز في عجمان',
    hero_subtitle_1: 'منذ عام 1990، نقدم تعليماً أكاديمياً راقياً من الروضة حتى الثانوية في 4 فروع',
    hero_title_2: 'تعليم متميز يؤسس للنجاح الأكاديمي والمهني',
    hero_subtitle_2: 'برامج تعليمية معتمدة ومعلمون مؤهلون يضمنون جودة التعليم',
    hero_title_3: '4 فروع في عجمان لتقديم خدمة تعليمية شاملة',
    hero_subtitle_3: 'النعيمية، التلة، الجرف، ومصفوت: مرافق حديثة ومعايير تربوية متقدمة',
    hero_title_4: 'سجل أبناءك الآن للعام الدراسي 2025-2026',
    hero_subtitle_4: 'التسجيل مفتوح في جميع المراحل: الروضة، الابتدائية، والثانوية للبنين والبنات',
    hero_title_5: 'بيئة تعليمية محفزة تُنمي المواهب وتُطلق الإبداع',
    hero_subtitle_5: 'برامج علمية وتقنية (STEM) وأنشطة لاصفية لبناء شخصيات متكاملة',
    about_subheading: 'عن مدرسة الحكمة الخاصة',
    about_headline: 'أكثر من 34 عاماً من التميز التعليمي في الإمارات',
    about_paragraph1: 'تأسست مدرسة الحكمة الخاصة في عام 1990 كواحدة من أعرق المؤسسات التعليمية في عجمان. نخدم حالياً أكثر من 1500 طالب وطالبة في 4 فروع تعليمية موزعة على مناطق استراتيجية: النعيمية، التلة، الجرف، ومصفوت.',
    about_paragraph2: 'نعتمد مناهج وزارة التربية والتعليم في دولة الإمارات مع إثراءات تعليمية تركز على تطوير مهارات القرن الحادي والعشرين، بما في ذلك برامج STEM، التفكير النقدي، والقيادة الطلابية.',
    about_paragraph3: 'تمتلك مدرستنا اعتمادات أكاديمية رسمية من وزارة التربية والتعليم، بالإضافة إلى جوائز دولية في التميز التعليمي والابتكار، مما يعكس التزامنا بأعلى معايير الجودة والتميز المؤسسي.',
    stats_founded: '1990',
    stats_students: '1500+',
    stats_branches: '4',
    programs_tag: 'البرامج التعليمية',
    programs_title: 'المراحل الدراسية في مدرسة الحكمة',
    programs_subtitle: 'تعليم متكامل من الروضة حتى الصف الثاني عشر يلبي احتياجات جميع المراحل العمرية',
    testimonial_tag: 'آراء الطلاب والخريجين',
    testimonial_title: 'تجارب من مدرسة الحكمة',
    testimonial_text1: '"درست في مدرسة الحكمة منذ الصف الأول، وكانت المدرسة بيتي الثاني طوال سنوات دراستي. هنا تعلمت القيم قبل العلم، وبُنيت شخصيتي خطوة بخطوة على يد معلمين مخلصين. اليوم وأنا خريج، أشعر بالفخر لانتمائي لمدرسة صنعت مستقبلي."',
    testimonial_author1: 'خريج مدرسة الحكمة',
    testimonial_role1: 'طالب سابق – المرحلة الثانوية',
    testimonial_text2: '"هذه شهادة تجريبية سيتم استبدالها لاحقًا بتجربة حقيقية لأحد أولياء الأمور أو الطلاب."',
    testimonial_author2: 'اسم تجريبي',
    testimonial_role2: 'وصف تجريبي',
    cta_text: 'سجل الآن للعام الدراسي 2025-2026',
    cta_button: 'تعرف على رؤيتنا وقيمنا'
  },
  goals: {
    page_title: 'رؤيتنا وقيمنا',
    hero_title: 'رؤيتنا وقيمنا',
    hero_subtitle: 'نؤمن بأن التعليم الحقيقي يبني الشخصيات ويُعدّ للأ_future',
    vision_title: 'رؤيتنا',
    vision_text: 'أن نكون Institution التعليمية الرائدة في المنطقة التي تُخرّج جيلاً واعياً، مبدعاً، قادراً على المنافسة عالمياً مع الحفاظ على هويته الثقافية العربية والإسلامية.',
    mission_title: 'رسالتنا',
    mission_text1: 'توفير بيئة تعليمية آمنة ومحفزة تُشجع على التفكير النقدي والابتكار.',
    mission_text2: 'تطوير مهارات القرن الحادي والعشرين بما في ذلك التواصل والتعاون والإبداع.',
    mission_text3: 'غرس القيم الأصيلة والمبادئ الأخلاقية في نفوس الطلاب.',
    mission_text4: 'بناء شراكات فعّالة مع أولياء الأمور والمجتمع.',
    values_title: 'قيمنا',
    value1_title: 'التميز',
    value1_text: 'نسعى دائماً للأفضل في كل ما نقدمه من خدمات تعليمية.',
    value2_title: 'الاحترام',
    value2_text: 'نحترم تنوع طلابنا ونقدر فروقهم الفردية.',
    value3_title: 'النزاهة',
    value3_text: 'نلتزم بأعلى معايير الصدق والأمانة في تعاملنا.',
    value4_title: 'الابتكار',
    value4_text: 'نتبنى الأفكار الجديدة ونسعى للتطوير المستمر.',
    value5_title: 'العمل الجماعي',
    value5_text: 'نؤمن بأن التعاون بين المعلمين والطلاب وأولياء الأمور يُحقق أفضل النتائج.',
    value6_title: 'المسؤولية',
    value6_text: 'نتحمل مسؤولية تعليمنا وتربيتنا لأبنائكم.'
  },
  admissions: {
    page_title: 'التسجيل',
    page_tag: 'انضم إلى مجتمعنا التعليمي',
    page_title_main: 'التسجيل للعام الدراسي 2025-2026',
    page_subtitle: 'سجّل أبناءك الآن في مدرسة الحكمة الخاصة واحصل على فرصة تعليمية استثنائية',
    hero_title: 'التسجيل',
    hero_subtitle: 'سجّل أبناءك في مدرسة الحكمة الخاصة',
    eligibility_title: 'المراحل الدراسية المقبولة',
    eligibility_kg: 'الروضة (KG1-KG2)',
    eligibility_primary: 'المرحلة الابتدائية (الصفوف 1-6)',
    eligibility_boys: 'المرحلة الثانوية للبنين (الصفوف 7-12)',
    eligibility_girls: 'المرحلة الثانوية للبنات (الصفوف 7-12)',
    process_title: 'إجراءات التسجيل',
    process_step1_title: 'ملء استمارة التسجيل',
    process_step1_text: 'قم بملء استمارة التسجيل الإلكترونية أدناه بدقة.',
    process_step2_title: 'إرفاق المستندات',
    process_step2_text: 'ص原件 أو نسخة إلكترونية من المستندات المطلوبة.',
    process_step3_title: 'المقابلة',
    process_step3_text: 'سيتم الاتصال بكم لتحديد موعد المقابلة والاختبارات.',
    process_step4_title: 'الدفع',
    process_step4_text: 'بعد القبول، قم بسداد الرسوم الدراسية.',
    documents_title: 'المستندات المطلوبة',
    documents_birth: 'شهادة ميلاد الطفل',
    documents_passport: 'جواز السفر (إن وجد)',
    documents_id: 'الهوية الوطنية للطالب وأولياء الأمور',
    documents_grade: 'شهادة الدرجات السابقة',
    documents_transfer: 'شهادة حسن سلوك (للطلاب المنقولين)',
    documents_health: 'تقرير طبي يوضح الحالة الصحية للطالب',
    fees_title: 'الرسوم الدراسية',
    fees_kg: 'مرحلة الروضة',
    fees_primary: 'المرحلة الابتدائية',
    fees_secondary: 'المرحلة الثانوية',
    fees_note: '* الرسوم المذكورة قابلة للتغيير. يُرجى الاتصال بالمدرسة للحصول على أحدث المعلومات.',
    contact_title: 'للتساؤلات',
    contact_text: 'لمزيد من المعلومات حول التسجيل، يرجى الاتصال بنا أو زيارة أقرب فرع.',
    form_title: 'استمارة التسجيل',
    form_name: 'اسم الطالب الكامل',
    form_dob: 'تاريخ الميلاد',
    form_gender: 'الجنس',
    form_male: 'ذكر',
    form_female: 'أنثى',
    form_nationality: 'الجنسية',
    form_phone: 'رقم الهاتف',
    form_email: 'البريد الإلكتروني',
    form_grade: 'الصف المطلوب',
    form_branch: 'الفرع المفضل',
    form_message: 'ملاحظات إضافية',
    form_submit: 'إرسال طلب التسجيل',
    form_success: 'تم استلام طلبكم بنجاح. سنتواصل معكم قريباً.',
    branch_nuaimiyah: 'النعيمية',
    branch_tela: 'التلة',
    branch_jarf: 'الجرف',
    branch_masfout: 'مصفوت'
  },
  branches: {
    page_title: 'فروعنا',
    hero_title: 'فروعنا',
    hero_subtitle: '4 فروع في عجمان لخدمتكم',
    intro_title: 'مواقعنا في عجمان',
    intro_text: 'نفتخر بوجود 4 فروع تعليمية موزعة على مناطق استراتيجية في عجمان، مما يتيح لأولياء الأمور اختيار الأقرب لمنازلهم.',
    nuaimiyah_title: 'فرع النعيمية',
    nuaimiyah_address: 'النعيمية، عجمان',
    nuaimiyah_phone: '06-7464040',
    nuaimiyah_email: 'info@alhikmahps.com',
    nuaimiyah_map: 'https://maps.google.com/?q=Al+Hikmah+Private+School+Nuaimiyah+Ajman',
    telah_title: 'فرع التلة',
    telah_address: 'التلة، عجمان',
    telah_phone: '06-7464040',
    telah_email: 'info@alhikmahps.com',
    telah_map: 'https://maps.google.com/?q=Al+Hikmah+Private+School+Tela+Ajman',
    jarf_title: 'فرع الجرف',
    jarf_address: 'الجرف، عجمان',
    jarf_phone: '06-7415050',
    jarf_email: 'info@alhikmahps.com',
    jarf_map: 'https://maps.google.com/?q=Al+Hikmah+Private+School+Jarf+Ajman',
    masfout_title: 'فرع مصفوت',
    masfout_address: 'مصفوت، عجمان',
    masfout_phone: '04-8522237',
    masfout_email: 'info@alhikmahps.com',
    masfout_map: 'https://maps.google.com/?q=Al+Hikmah+Private+School+Masfout+Ajman',
    cta_title: 'احجز جولة في مدرستنا',
    cta_text: 'زر أحد فروعنا لترى بنفسك بيئة التعلم المتميزة التي نقدمها.',
    cta_button: 'احجز الآن'
  },
  careers: {
    page_title: 'الوظائف',
    hero_title: 'انضم إلى فريقنا',
    hero_subtitle: 'نبحث عن معلمين متميزين للانضمام إلى مدرستنا',
    intro_title: 'فرص عمل في مدرسة الحكمة الخاصة',
    intro_text: 'نحن نبحث عن معلمين مؤهلين Passionate教书مهنهم يشاركوننا رؤيتنا في تقديم تعليم استثنائي.',
    benefits_title: 'المزايا',
    benefit1: 'بيئة عمل محفزة وداعمة',
    benefit2: 'فرص للتطوير المهني المستمر',
    benefit3: 'رواتب تنافسية',
    benefit4: 'تأمين صحي',
    benefit5: 'إجازات سنوية',
    benefit6: 'عمل مع طلاب متميزين',
    openings_title: 'الوظائف الشاغرة',
    opening1_title: 'معلم لغة عربية',
    opening1_location: 'فرع الجرف',
    opening1_type: 'دوام كامل',
    opening2_title: 'معلم رياضيات',
    opening2_location: 'فرع النعيمية',
    opening2_type: 'دوام كامل',
    opening3_title: 'معلم علوم',
    opening3_location: 'فرع التلة',
    opening3_type: 'دوام كامل',
    opening4_title: 'معلم لغة إنجليزية',
    opening4_location: 'فرع مصفوت',
    opening4_type: 'دوام كامل',
    apply_title: 'قدم الآن',
    apply_text: 'إذا كنت مهتماً بأي من هذه الوظائف، أرسل سيرتك الذاتية على البريد الإلكتروني أدناه.',
    apply_email: 'careers@alhikmahps.com',
    form_name: 'الاسم الكامل',
    form_email: 'البريد الإلكتروني',
    form_phone: 'رقم الهاتف',
    form_position: 'الوظيفة المتقدم لها',
    form_experience: 'سنوات الخبرة',
    form_qualifications: 'المؤهلات',
    form_cv: 'السيرة الذاتية',
    form_message: 'رسالة تغطية',
    form_submit: 'إرسال الطلب',
    form_success: 'تم استلام طلبك بنجاح. سنتواصل معك إذا تم اختيارك.'
  },
  footer: {
    copyright: '© 2024 مدرسة الحكمة الخاصة. جميع الحقوق محفوظة.',
    email: 'info@alhikmahps.com',
    nuaimiyah_label: 'النعيمية:',
    nuaimiyah_phone: '06-7464040',
    jarf_label: 'الجرف:',
    jarf_phone: '06-7415050',
    masfout_label: 'مصفوت:',
    masfout_phone: '04-8522237',
    telah_label: 'التلة:',
    telah_phone: '06-7464040',
    quick_about: 'عن الحكمة',
    quick_programs: 'برامجنا',
    quick_admissions: 'التسجيل',
    youtube_url: 'https://www.youtube.com/@alhikmahprivateschoolajman6525',
    instagram_url: 'https://www.instagram.com/hikmahps92/',
    facebook_url: 'https://www.facebook.com/alhikmahps',
    snapchat_url: 'https://www.snapchat.com/add/alhikmahps'
  },
  navigation: {
    home: 'الرئيسية',
    goals: 'رؤيتنا',
    admissions: 'التسجيل',
    branches: 'فروعنا',
    careers: 'الوظائف',
    about: 'عن الحكمة',
    programs: 'برامجنا',
    register: 'سجل الآن'
  },
  header: {
    search_placeholder: 'ابحث هنا...'
  }
};

async function seed() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');

    const Content = mongoose.model('Content', new mongoose.Schema({
      section: { type: String, required: true, index: true },
      field: { type: String, required: true, index: true },
      publishedValue: { type: mongoose.Schema.Types.Mixed, default: '' },
      draftValue: { type: mongoose.Schema.Types.Mixed, default: undefined },
      hasDraft: { type: Boolean, default: false },
      version: { type: Number, default: 1 },
      history: [{
        version: { type: Number, required: true },
        value: { type: mongoose.Schema.Types.Mixed, required: true },
        publishedAt: { type: Date, default: Date.now },
        publishedBy: { type: String, default: 'seed-script' }
      }],
      type: { type: String, default: 'text' },
      lastEditedAt: { type: Date, default: null },
      lastEditedBy: { type: String, default: null },
      lastPublishedAt: { type: Date, default: null },
      lastPublishedBy: { type: String, default: null }
    }, {
      timestamps: true
    }));

    await Content.deleteMany({});

    const bulkOps = [];
    for (const [section, fields] of Object.entries(contentData)) {
      for (const [field, value] of Object.entries(fields)) {
        bulkOps.push({
          updateOne: {
            filter: { section, field },
            update: {
              $set: {
                section,
                field,
                publishedValue: value,
                draftValue: undefined,
                hasDraft: false,
                version: 1,
                history: [{
                  version: 1,
                  value,
                  publishedAt: new Date(),
                  publishedBy: 'seed-script'
                }],
                type: 'text',
                lastEditedAt: new Date(),
                lastEditedBy: 'seed-script',
                lastPublishedAt: new Date(),
                lastPublishedBy: 'seed-script',
                updatedAt: new Date()
              }
            },
            upsert: true
          }
        });
      }
    }

    await Content.bulkWrite(bulkOps);
    console.log(`Seeded ${bulkOps.length} content items successfully`);
    
    process.exit(0);
  } catch (error) {
    console.error('Error seeding content:', error);
    process.exit(1);
  }
}

seed();
